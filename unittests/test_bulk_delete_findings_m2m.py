"""
Unit tests for M2M through-table clearing in the chunked bulk finding delete.

The chunked finding delete clears M2M through rows once up front for the whole
queryset, but deletes the findings themselves in per-chunk transactions. A
through row that appears after that one-shot pass survives into its chunk's
COMMIT and violates the through table's foreign key.
"""

import logging

from django.db import connection
from django.utils import timezone

from dojo import utils_cascade_delete
from dojo.finding.helper import bulk_delete_findings
from dojo.models import (
    Engagement,
    Finding,
    Notes,
    Product,
    Product_Type,
    Test,
    Test_Type,
    User,
    UserContactInfo,
)

from .dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)


class TestBulkDeleteFindingsM2M(DojoTestCase):

    """M2M through rows must not outlive the findings they point at."""

    def setUp(self):
        super().setUp()
        self.testuser = User.objects.create(
            username="bulk_delete_m2m_user",
            is_staff=True,
            is_superuser=True,
        )
        UserContactInfo.objects.create(user=self.testuser, block_execution=True)
        self.system_settings(enable_deduplication=False)
        self.system_settings(enable_product_grade=False)

        self.product_type = Product_Type.objects.create(name="Bulk Delete M2M PT")
        self.product = Product.objects.create(
            name="Bulk Delete M2M Product",
            description="Test",
            prod_type=self.product_type,
        )
        self.test_type = Test_Type.objects.get_or_create(name="Manual Test")[0]
        self.engagement = Engagement.objects.create(
            name="Bulk Delete M2M Engagement",
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
        )

    def _add_note(self, finding, entry):
        note = Notes.objects.create(entry=entry, author=self.testuser)
        finding.notes.add(note)
        return note

    def _delete_with_write_before_last_chunk(self, findings, attach_to, attach):
        """
        Delete ``findings`` one chunk at a time, writing to ``attach_to`` partway through.

        ``attach`` is invoked from inside the delete, after the first chunk has been
        handled and before ``attach_to``'s own chunk is reached. That is the interleaving
        a concurrent writer produces in production: a note or tag lands on a finding that
        the running delete has already selected but not yet reached.
        """
        # The delete imports execute_delete_sql at call time, so the patch has to land
        # on the defining module rather than on dojo.finding.helper.
        real_execute_delete_sql = utils_cascade_delete.execute_delete_sql
        state = {"calls": 0}

        def execute_delete_sql_with_concurrent_write(queryset, *args, **kwargs):
            result = real_execute_delete_sql(queryset, *args, **kwargs)
            state["calls"] += 1
            if state["calls"] == 1:
                attach()
            return result

        utils_cascade_delete.execute_delete_sql = execute_delete_sql_with_concurrent_write
        try:
            bulk_delete_findings(
                Finding.objects.filter(id__in=[finding.id for finding in findings]),
                chunk_size=1,
            )
        finally:
            utils_cascade_delete.execute_delete_sql = real_execute_delete_sql
        return state["calls"]

    def test_note_added_during_delete_does_not_dangle(self):
        """
        A note attached mid-delete must be cleared with its finding's chunk.

        Django declares its foreign keys DEFERRABLE INITIALLY DEFERRED, so in production
        the leftover through row is only rejected at the chunk's COMMIT -- far from the
        code that created it, surfacing as an opaque constraint error on the delete task.
        Inside a TestCase transaction the same condition is what check_constraints()
        reports.
        """
        first = self._create_finding("M2M F1")
        second = self._create_finding("M2M F2")
        self._add_note(first, "note on the first finding")

        self._delete_with_write_before_last_chunk(
            [first, second],
            second,
            lambda: self._add_note(second, "note that lands mid-delete"),
        )

        self.assertFalse(
            Finding.objects.filter(id__in=[first.id, second.id]).exists(),
            "Both findings should have been deleted.",
        )
        self.assertFalse(
            Finding.notes.through.objects.filter(finding_id__in=[first.id, second.id]).exists(),
            "No note through row may outlive the finding it points at.",
        )
        # The check Postgres runs at COMMIT, where a leftover through row is the
        # IntegrityError that fails the delete in production.
        connection.check_constraints()

    def test_tag_added_during_delete_does_not_dangle(self):
        """Same window, reached through the tag through table rather than notes."""
        first = self._create_finding("M2M F3")
        second = self._create_finding("M2M F4")
        first.tags = ["tag-on-first"]
        first.save()

        def add_tag_to_second():
            second.tags = ["tag-that-lands-mid-delete"]
            second.save()

        self._delete_with_write_before_last_chunk([first, second], second, add_tag_to_second)

        self.assertFalse(
            Finding.objects.filter(id__in=[first.id, second.id]).exists(),
            "Both findings should have been deleted.",
        )
        self.assertFalse(
            Finding.tags.through.objects.filter(finding_id__in=[first.id, second.id]).exists(),
            "No tag through row may outlive the finding it points at.",
        )
        connection.check_constraints()

    def test_notes_cleared_without_concurrent_write(self):
        """Control: the ordinary path still clears notes and their Notes rows."""
        first = self._create_finding("M2M F5")
        second = self._create_finding("M2M F6")
        note = self._add_note(first, "note on the first finding")
        self._add_note(second, "note on the second finding")

        bulk_delete_findings(
            Finding.objects.filter(id__in=[first.id, second.id]),
            chunk_size=1,
        )

        self.assertFalse(
            Finding.objects.filter(id__in=[first.id, second.id]).exists(),
            "Both findings should have been deleted.",
        )
        self.assertFalse(
            Finding.notes.through.objects.filter(finding_id__in=[first.id, second.id]).exists(),
            "Note through rows should be gone.",
        )
        self.assertFalse(
            Notes.objects.filter(id=note.id).exists(),
            "The orphaned Notes row should be deleted along with the finding.",
        )
        connection.check_constraints()
