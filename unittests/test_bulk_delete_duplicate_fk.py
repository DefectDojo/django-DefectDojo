"""
Regression: bulk_delete_findings raised IntegrityError on the self-referential
dojo_finding.duplicate_finding_id FK when a surviving finding still pointed at a
deleted one (seen in production via dojo.tasks.async_dupe_delete).
"""

import logging

from django.db import IntegrityError, connection
from django.utils import timezone
from parameterized import parameterized

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


class TestBulkDeleteDuplicateFindingFK(DojoTestCase):

    """
    bulk_delete_findings must never leave a dangling duplicate_finding_id.

    ``Finding.duplicate_finding`` is a self-FK with ``on_delete=DO_NOTHING``, so
    Django performs no cleanup and Postgres enforces the constraint at COMMIT.
    ``_bulk_delete_findings_internal`` passes ``skip_relations={Finding}`` to the
    cascade walker, so nothing clears the pointer for findings that survive the
    delete.
    """

    def setUp(self):
        super().setUp()
        self.testuser = User.objects.create(
            username="bulk_delete_dupe_fk_user",
            is_staff=True,
            is_superuser=True,
        )
        UserContactInfo.objects.create(user=self.testuser, block_execution=True)
        self.system_settings(enable_deduplication=False)
        self.system_settings(enable_product_grade=False)

        self.product_type = Product_Type.objects.create(name="Bulk Delete Dupe FK PT")
        self.product = Product.objects.create(
            name="Bulk Delete Dupe FK Product",
            description="Test",
            prod_type=self.product_type,
        )
        self.test_type = Test_Type.objects.get_or_create(name="Manual Test")[0]
        self.engagement = Engagement.objects.create(
            name="Bulk Delete Dupe FK Engagement",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.test = Test.objects.create(
            engagement=self.engagement,
            test_type=self.test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

    def _create_finding(self, title, *, duplicate_of=None):
        return Finding.objects.create(
            test=self.test,
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
    def _assert_no_deferred_fk_violation():
        """Force Postgres to validate the deferred FKs the way COMMIT would."""
        try:
            connection.check_constraints()
        except IntegrityError as exc:  # pragma: no cover - only on regression
            msg = f"bulk_delete_findings left a dangling duplicate_finding_id: {exc}"
            raise AssertionError(msg) from exc

    @parameterized.expand([
        # (scenario, referrer_is_in_delete_set)
        ("referrer_outside_delete_set", False),
        ("referrer_inside_delete_set", True),
    ])
    def test_bulk_delete_clears_dangling_duplicate_finding(self, scenario, referrer_in_delete_set):
        """
        Deleting a finding that is itself an original must not orphan its cluster.

        The failing case is a transitive duplicate chain (original <- middle <- tail)
        where only ``middle`` is selected for deletion, exactly what
        ``async_dupe_delete`` does when it deletes excess duplicates: ``tail``
        survives and still references the deleted ``middle``.

        The control case deletes both, which already worked, so the fix is locked
        in both directions.
        """
        original = self._create_finding("original")
        middle = self._create_finding("middle", duplicate_of=original)
        tail = self._create_finding("tail", duplicate_of=middle)

        delete_ids = [middle.id, tail.id] if referrer_in_delete_set else [middle.id]

        bulk_delete_findings(Finding.objects.filter(id__in=delete_ids), order_desc=True)
        self._assert_no_deferred_fk_violation()

        self.assertFalse(
            Finding.objects.filter(id__in=delete_ids).exists(),
            msg=f"[{scenario}] expected findings {delete_ids} to be deleted",
        )
        self.assertFalse(
            Finding.objects.filter(duplicate_finding_id=middle.id).exists(),
            msg=(
                "expected no surviving finding to reference deleted finding "
                f"{middle.id}, found "
                f"{list(Finding.objects.filter(duplicate_finding_id=middle.id).values_list('id', flat=True))}"
            ),
        )

        if not referrer_in_delete_set:
            tail.refresh_from_db()
            self.assertIsNone(
                tail.duplicate_finding_id,
                msg=f"expected tail.duplicate_finding_id=None, persisted={tail.duplicate_finding_id}",
            )
            self.assertFalse(
                tail.duplicate,
                msg=f"expected tail.duplicate=False, persisted={tail.duplicate}",
            )

    def test_bulk_delete_clears_dangling_references_in_every_chunk(self):
        """
        Every chunk must clean up its own referrers, not just the first one.

        Each chunk commits separately in production, so a chunk that leaves a
        dangling pointer fails on its own COMMIT. Two originals are deleted with
        chunk_size=1 (one chunk each), each with a surviving duplicate outside the
        deletion set.
        """
        original_a = self._create_finding("chunked original A")
        original_b = self._create_finding("chunked original B")
        survivor_a = self._create_finding("survivor A", duplicate_of=original_a)
        survivor_b = self._create_finding("survivor B", duplicate_of=original_b)

        bulk_delete_findings(
            Finding.objects.filter(id__in=[original_a.id, original_b.id]),
            chunk_size=1,
            order_desc=True,
        )
        self._assert_no_deferred_fk_violation()

        for survivor in (survivor_a, survivor_b):
            survivor.refresh_from_db()
            self.assertIsNone(
                survivor.duplicate_finding_id,
                msg=(
                    f"expected {survivor.title}.duplicate_finding_id=None, "
                    f"persisted={survivor.duplicate_finding_id}"
                ),
            )
