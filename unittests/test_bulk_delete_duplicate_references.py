"""
Unit tests for inbound ``duplicate_finding`` references in the chunked bulk finding delete.

The duplicate_finding self-FK is ON DELETE DO_NOTHING and DEFERRABLE INITIALLY DEFERRED,
so a surviving finding left pointing at a deleted one is only rejected at COMMIT -- as an
opaque constraint error that takes the whole chunk down. Resolving those references is
done by ``bulk_delete_findings`` itself, inside each chunk's transaction, so it covers
every entry point and no window exists between resolving and committing.
"""

import logging
from unittest.mock import patch

from django.db import connection
from django.utils import timezone

from dojo import utils_cascade_delete
from dojo.finding.helper import bulk_delete_findings
from dojo.models import (
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
    User,
    UserContactInfo,
)

from .dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)


class TestBulkDeleteDuplicateReferences(DojoTestCase):

    """No surviving finding may still point at a finding the delete removed."""

    def setUp(self):
        super().setUp()
        self.testuser = User.objects.create(
            username="bulk_delete_dupe_ref_user",
            is_staff=True,
            is_superuser=True,
        )
        UserContactInfo.objects.create(user=self.testuser, block_execution=True)
        self.system_settings(enable_deduplication=False, enable_product_grade=False)

        self.product_type = Product_Type.objects.create(name="Bulk Delete Dupe Ref PT")
        self.product = Product.objects.create(
            name="Bulk Delete Dupe Ref Product",
            description="Test",
            prod_type=self.product_type,
        )
        self.test_type = Test_Type.objects.get_or_create(name="Manual Test")[0]
        self.engagement = Engagement.objects.create(
            name="Bulk Delete Dupe Ref Engagement",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.test = self._create_test()

    def _create_test(self):
        return Test.objects.create(
            engagement=self.engagement,
            test_type=self.test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

    def _create_finding(self, title, duplicate_of=None, test=None):
        return Finding.objects.create(
            test=test or self.test,
            title=title,
            severity="High",
            description="Test",
            mitigation="Test",
            impact="Test",
            reporter=self.testuser,
            duplicate=duplicate_of is not None,
            duplicate_finding=duplicate_of,
        )

    @staticmethod
    def _point_at(finding, original):
        """Wire a duplicate link directly, bypassing set_duplicate's chain normalization."""
        Finding.objects.filter(id=finding.id).update(
            duplicate=True,
            duplicate_finding_id=original.id,
        )

    def _delete_with_reference_written_mid_delete(self, doomed, write_reference):
        """
        Delete ``doomed`` one finding per chunk, writing a duplicate reference partway through.

        ``write_reference`` fires from inside the first chunk, once its findings are gone
        and before any later chunk is reached. That is the interleaving a concurrent
        import produces in production: dedupe points a finding at an original the running
        delete has already selected but not yet removed.
        """
        real_execute_delete_sql = utils_cascade_delete.execute_delete_sql
        state = {"calls": 0}

        def execute_delete_sql_with_concurrent_write(queryset, *args, **kwargs):
            result = real_execute_delete_sql(queryset, *args, **kwargs)
            state["calls"] += 1
            if state["calls"] == 1:
                write_reference()
            return result

        # bulk_delete_findings imports execute_delete_sql at call time, so the patch has
        # to land on the defining module rather than on dojo.finding.helper.
        with patch.object(
            utils_cascade_delete,
            "execute_delete_sql",
            execute_delete_sql_with_concurrent_write,
        ):
            bulk_delete_findings(
                Finding.objects.filter(id__in=[finding.id for finding in doomed]),
                chunk_size=1,
                order_desc=True,
            )
        return state["calls"]

    def test_chained_reference_is_repointed_for_any_caller(self):
        """
        A chained duplicate must be resolved by the delete primitive, not by one caller.

        This goes straight through bulk_delete_findings rather than the excess-duplicate
        task, which is the only caller that used to resolve these references itself.
        """
        root = self._create_finding("Chain root")
        doomed = self._create_finding("Chain doomed", duplicate_of=root)
        survivor = self._create_finding("Chain survivor")
        self._point_at(survivor, doomed)

        bulk_delete_findings(Finding.objects.filter(id=doomed.id), order_desc=True)

        self.assertFalse(
            Finding.objects.filter(id=doomed.id).exists(),
            "The doomed duplicate should have been deleted despite the chained reference.",
        )
        survivor.refresh_from_db()
        self.assertEqual(
            survivor.duplicate_finding_id, root.id,
            msg=(
                "the survivor should have been re-pointed at the chain's surviving root, "
                f"persisted duplicate_finding_id={survivor.duplicate_finding_id}"
            ),
        )
        self.assertTrue(survivor.duplicate, "re-pointing at a surviving root keeps it a duplicate.")
        connection.check_constraints()

    def test_scoped_delete_without_order_desc_resolves_inbound_references(self):
        """
        The ascending, scope-filtered shape used when a Test/Engagement/Product cascades.

        That caller reconciles duplicates before calling in, so nothing here should have
        been left over -- which is exactly why the gap went unnoticed. The delete itself
        has to hold the invariant.
        """
        other_test = self._create_test()
        root = self._create_finding("Scoped root", test=other_test)
        doomed = self._create_finding("Scoped doomed", duplicate_of=root)
        survivor = self._create_finding("Scoped survivor", test=other_test)
        self._point_at(survivor, doomed)

        bulk_delete_findings(Finding.objects.filter(test=self.test))

        self.assertFalse(
            Finding.objects.filter(id=doomed.id).exists(),
            "The in-scope finding should have been deleted.",
        )
        survivor.refresh_from_db()
        self.assertEqual(
            survivor.duplicate_finding_id, root.id,
            msg=(
                "an out-of-scope survivor should have been re-pointed, "
                f"persisted duplicate_finding_id={survivor.duplicate_finding_id}"
            ),
        )
        connection.check_constraints()

    def test_chain_is_walked_through_several_doomed_ancestors(self):
        """
        A chain running through more than one doomed finding resolves to the surviving root.

        Stopping at the first ancestor would find another doomed finding and promote the
        survivor to an original, silently breaking a cluster that has a perfectly good
        root still standing.
        """
        root = self._create_finding("Deep chain root")
        doomed_lower = self._create_finding("Deep chain doomed lower", duplicate_of=root)
        doomed_upper = self._create_finding("Deep chain doomed upper")
        self._point_at(doomed_upper, doomed_lower)
        survivor = self._create_finding("Deep chain survivor")
        self._point_at(survivor, doomed_upper)

        bulk_delete_findings(
            Finding.objects.filter(id__in=[doomed_lower.id, doomed_upper.id]),
            chunk_size=1,
            order_desc=True,
        )

        self.assertFalse(
            Finding.objects.filter(id__in=[doomed_lower.id, doomed_upper.id]).exists(),
            "Both findings in the chain should have been deleted.",
        )
        survivor.refresh_from_db()
        self.assertEqual(
            survivor.duplicate_finding_id, root.id,
            msg=(
                "the survivor should have been re-pointed past both doomed ancestors, "
                f"persisted duplicate_finding_id={survivor.duplicate_finding_id}"
            ),
        )
        self.assertTrue(survivor.duplicate, "the survivor is still a duplicate, now of the root.")
        connection.check_constraints()

    def test_reference_written_mid_delete_is_repointed(self):
        """
        A reference that lands mid-delete must be resolved in its chunk's transaction.

        Resolving once up front cannot see this write: it happens after that pass and
        before the chunk holding its target commits.
        """
        original = self._create_finding("Mid-delete original")
        doomed_first = self._create_finding("Mid-delete doomed A", duplicate_of=original)
        doomed_second = self._create_finding("Mid-delete doomed B", duplicate_of=original)
        survivor = self._create_finding("Mid-delete survivor")

        # order_desc deletes the higher id first, so doomed_first is still present when the
        # reference is written and is removed by a later chunk.
        self._delete_with_reference_written_mid_delete(
            [doomed_first, doomed_second],
            lambda: self._point_at(survivor, doomed_first),
        )

        self.assertFalse(
            Finding.objects.filter(id__in=[doomed_first.id, doomed_second.id]).exists(),
            "Both findings should have been deleted.",
        )
        survivor.refresh_from_db()
        self.assertEqual(
            survivor.duplicate_finding_id, original.id,
            msg=(
                "the survivor should have been re-pointed at the surviving original, "
                f"persisted duplicate_finding_id={survivor.duplicate_finding_id}"
            ),
        )
        # The check Postgres runs at COMMIT, where a leftover reference is the
        # IntegrityError that fails the delete in production.
        connection.check_constraints()

    def test_survivor_is_promoted_when_no_root_survives(self):
        """Same window, but the doomed finding has no surviving ancestor to inherit."""
        doomed_first = self._create_finding("Orphan doomed A")
        doomed_second = self._create_finding("Orphan doomed B")
        survivor = self._create_finding("Orphan survivor")

        self._delete_with_reference_written_mid_delete(
            [doomed_first, doomed_second],
            lambda: self._point_at(survivor, doomed_first),
        )

        self.assertFalse(
            Finding.objects.filter(id__in=[doomed_first.id, doomed_second.id]).exists(),
            "Both findings should have been deleted.",
        )
        survivor.refresh_from_db()
        self.assertIsNone(
            survivor.duplicate_finding_id,
            msg=(
                "with no surviving root the survivor should be promoted, "
                f"persisted duplicate_finding_id={survivor.duplicate_finding_id}"
            ),
        )
        self.assertFalse(survivor.duplicate, "a promoted finding is no longer flagged as a duplicate.")
        connection.check_constraints()

    def test_only_references_into_the_delete_are_touched(self):
        """
        Resolving inbound references must not disturb anything else.

        A duplicate that already points at the surviving original is not part of this
        delete and has to come through it untouched -- re-pointing or promoting it would
        silently rewrite duplicate clusters on every delete.
        """
        original = self._create_finding("Scoping original")
        doomed_first = self._create_finding("Scoping doomed A", duplicate_of=original)
        doomed_second = self._create_finding("Scoping doomed B", duplicate_of=original)
        survivor_of_doomed = self._create_finding("Scoping survivor of doomed")
        survivor_of_original = self._create_finding(
            "Scoping survivor of original", duplicate_of=original,
        )

        self._delete_with_reference_written_mid_delete(
            [doomed_first, doomed_second],
            lambda: self._point_at(survivor_of_doomed, doomed_first),
        )

        survivor_of_doomed.refresh_from_db()
        self.assertEqual(
            survivor_of_doomed.duplicate_finding_id, original.id,
            "the reference into the delete should have been resolved.",
        )

        survivor_of_original.refresh_from_db()
        self.assertEqual(
            survivor_of_original.duplicate_finding_id, original.id,
            msg=(
                "a duplicate of the surviving original is out of scope and must be left as-is, "
                f"persisted duplicate_finding_id={survivor_of_original.duplicate_finding_id}"
            ),
        )
        self.assertTrue(
            survivor_of_original.duplicate,
            "an out-of-scope duplicate must not be promoted to an original.",
        )

        original.refresh_from_db()
        self.assertIsNone(
            original.duplicate_finding_id,
            "the surviving original must not be touched by the delete.",
        )
        self.assertFalse(original.duplicate, "the surviving original must stay an original.")
        connection.check_constraints()

    def test_ordinary_delete_is_unchanged(self):
        """Control: with no inbound references the ordinary path behaves as before."""
        original = self._create_finding("Control original")
        doomed_first = self._create_finding("Control doomed A", duplicate_of=original)
        doomed_second = self._create_finding("Control doomed B", duplicate_of=original)
        survivor = self._create_finding("Control survivor", duplicate_of=original)

        bulk_delete_findings(
            Finding.objects.filter(id__in=[doomed_first.id, doomed_second.id]),
            chunk_size=1,
            order_desc=True,
        )

        self.assertFalse(
            Finding.objects.filter(id__in=[doomed_first.id, doomed_second.id]).exists(),
            "Both excess duplicates should have been deleted.",
        )
        survivor.refresh_from_db()
        self.assertEqual(
            survivor.duplicate_finding_id, original.id,
            "an untouched duplicate keeps pointing at its original.",
        )
        self.assertTrue(survivor.duplicate, "an untouched duplicate stays a duplicate.")
        connection.check_constraints()
