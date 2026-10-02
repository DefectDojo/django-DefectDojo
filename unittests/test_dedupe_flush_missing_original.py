"""
Tests for _flush_duplicate_changes() in dojo.finding.deduplication.

Batch deduplication reads its candidate originals near the start of a batch and
persists the resulting ``duplicate_finding`` links at the end of it. When an original
is deleted in between -- the excess-duplicate delete task runs on its own schedule --
the deferred self-FK rejects the whole write at COMMIT, so no finding in the batch
gets deduplicated and the post-processing task fails.
"""

import logging

from django.db import connection
from django.utils import timezone

from dojo.finding.deduplication import _flush_duplicate_changes  # noqa: PLC2701
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


# Regression: post-processing a batch of findings aborted at COMMIT with
# "insert or update on table dojo_finding violates foreign key constraint
# dojo_finding_duplicate_finding_id_... Key (duplicate_finding_id)=(N) is not
# present in table dojo_finding" when the matched original was deleted while the
# batch was being processed.
class TestFlushDuplicateChangesMissingOriginal(DojoTestCase):

    """A batch must not write a duplicate link to a finding that no longer exists."""

    def setUp(self):
        super().setUp()
        self.testuser = User.objects.create(
            username="dedupe_flush_user",
            is_staff=True,
            is_superuser=True,
        )
        UserContactInfo.objects.create(user=self.testuser, block_execution=True)
        self.system_settings(enable_deduplication=False)
        self.system_settings(enable_product_grade=False)

        self.product_type = Product_Type.objects.create(name="Dedupe Flush PT")
        self.product = Product.objects.create(
            name="Dedupe Flush Product",
            description="Test",
            prod_type=self.product_type,
        )
        self.test_type = Test_Type.objects.get_or_create(name="Manual Test")[0]
        self.engagement = Engagement.objects.create(
            name="Dedupe Flush Engagement",
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

    def _create_finding(self, title):
        return Finding.objects.create(
            test=self.test,
            title=title,
            severity="High",
            description="Test",
            mitigation="Test",
            impact="Test",
            reporter=self.testuser,
            active=True,
            verified=True,
        )

    @staticmethod
    def _mark_as_duplicate_in_memory(new_finding, original):
        """Apply what set_duplicate() applies, without persisting -- the batch's save=False path."""
        new_finding.duplicate = True
        new_finding.active = False
        new_finding.verified = False
        new_finding.duplicate_finding = original
        return new_finding

    def test_flush_skips_finding_whose_original_was_deleted(self):
        """
        A link to a vanished original is dropped instead of aborting the whole batch.

        The self-FK is DEFERRABLE INITIALLY DEFERRED, so in production the bad row is
        only rejected at COMMIT: the entire batch is rolled back and every other finding
        in it loses its deduplication too. Dropping the one unusable link keeps the rest
        of the batch.
        """
        surviving_original = self._create_finding("Flush surviving original")
        doomed_original = self._create_finding("Flush doomed original")
        keeps_its_link = self._create_finding("Flush duplicate with live original")
        loses_its_link = self._create_finding("Flush duplicate with deleted original")

        self._mark_as_duplicate_in_memory(keeps_its_link, surviving_original)
        self._mark_as_duplicate_in_memory(loses_its_link, doomed_original)

        # The excess-duplicate delete removes the original after the batch matched it.
        doomed_original_id = doomed_original.id
        Finding.objects.filter(id=doomed_original_id).delete()

        flushed = _flush_duplicate_changes([keeps_its_link, loses_its_link])

        keeps_its_link.refresh_from_db()
        self.assertEqual(
            keeps_its_link.duplicate_finding_id, surviving_original.id,
            msg=(
                "the rest of the batch must still be deduplicated, "
                f"persisted duplicate_finding_id={keeps_its_link.duplicate_finding_id}"
            ),
        )
        self.assertTrue(keeps_its_link.duplicate, "the usable link should have been persisted.")

        loses_its_link.refresh_from_db()
        self.assertIsNone(
            loses_its_link.duplicate_finding_id,
            msg=(
                "a link to a deleted original must not be written, "
                f"persisted duplicate_finding_id={loses_its_link.duplicate_finding_id}"
            ),
        )
        self.assertFalse(
            loses_its_link.duplicate,
            "the finding stays as it was rather than being marked a duplicate of nothing.",
        )
        self.assertTrue(
            loses_its_link.active,
            "the finding keeps the status it had before the unusable match.",
        )

        self.assertEqual(
            [finding.id for finding in flushed], [keeps_its_link.id],
            "only persisted findings are returned for follow-up processing.",
        )
        # The check Postgres runs at COMMIT, where the dangling link is the
        # IntegrityError that fails the batch in production.
        connection.check_constraints()

    def test_flush_persists_when_every_original_survives(self):
        """Control: the ordinary path writes every link and returns every finding."""
        original = self._create_finding("Flush control original")
        first_duplicate = self._create_finding("Flush control duplicate A")
        second_duplicate = self._create_finding("Flush control duplicate B")

        self._mark_as_duplicate_in_memory(first_duplicate, original)
        self._mark_as_duplicate_in_memory(second_duplicate, original)

        flushed = _flush_duplicate_changes([first_duplicate, second_duplicate])

        for duplicate in (first_duplicate, second_duplicate):
            duplicate.refresh_from_db()
            self.assertEqual(
                duplicate.duplicate_finding_id, original.id,
                msg=(
                    "every link should have been persisted, "
                    f"persisted duplicate_finding_id={duplicate.duplicate_finding_id}"
                ),
            )
            self.assertTrue(duplicate.duplicate)
            self.assertFalse(duplicate.active)

        self.assertEqual(
            sorted(finding.id for finding in flushed),
            sorted([first_duplicate.id, second_duplicate.id]),
            "all persisted findings are returned for follow-up processing.",
        )
        connection.check_constraints()

    def test_flush_of_findings_without_a_link_is_unchanged(self):
        """Findings promoted to originals carry a null link and must still be written."""
        promoted = self._create_finding("Flush promoted finding")
        promoted.duplicate = False
        promoted.duplicate_finding = None
        promoted.active = False

        flushed = _flush_duplicate_changes([promoted])

        promoted.refresh_from_db()
        self.assertIsNone(promoted.duplicate_finding_id)
        self.assertFalse(promoted.duplicate)
        self.assertFalse(promoted.active, "the promoted finding's other fields are still written.")
        self.assertEqual([finding.id for finding in flushed], [promoted.id])
        connection.check_constraints()

    def test_flush_of_an_empty_batch_is_a_no_op(self):
        """Control: nothing to write, nothing returned."""
        self.assertEqual(_flush_duplicate_changes([]), [])
