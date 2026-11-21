from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils.timezone import now

from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    NoteHistory,
    Notes,
    Product,
    Product_Type,
    Test,
    Test_Type,
)
from dojo.notes.helper import delete_related_notes


class TestDeleteRelatedNotesInBulk(TestCase):

    """
    Regression: deleting an object's notes deleted each note's edit history from the per-note pre_delete receiver
    (dojo.notes.signals), about four queries per note, so deleting a finding with a hundred notes ran some 500 queries.
    delete_related_notes now deletes every note and every history row in a fixed number of queries. The receiver still
    cleans up a note deleted on its own.
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User.objects.create(username="notes_bulk_user")
        product = Product.objects.create(
            name="Notes Bulk Product",
            prod_type=Product_Type.objects.create(name="Notes Bulk Product Type"),
            description="notes bulk",
        )
        engagement = Engagement.objects.create(
            name="Notes Bulk Engagement", product=product, target_start=now(), target_end=now(),
        )
        cls.test = Test.objects.create(
            title="Notes Bulk Test",
            engagement=engagement,
            test_type=Test_Type.objects.create(name="Notes Bulk Test Type"),
            target_start=now(),
            target_end=now(),
        )

    def _finding_with_notes(self, count):
        finding = Finding.objects.create(
            title=f"Notes Bulk {count}", test=self.test, reporter=self.user, severity="High",
        )
        for n in range(count):
            note = Notes.objects.create(entry=f"note {n}", author=self.user)
            note.history.add(
                NoteHistory.objects.create(data=f"first {n}", current_editor=self.user),
                NoteHistory.objects.create(data=f"second {n}", current_editor=self.user),
            )
            finding.notes.add(note)
        note_ids = list(finding.notes.values_list("id", flat=True))
        history_ids = list(Notes.history.through.objects.filter(notes__in=note_ids).values_list("notehistory_id", flat=True))
        return finding, note_ids, history_ids

    def _delete(self, count):
        finding, note_ids, history_ids = self._finding_with_notes(count)
        with CaptureQueriesContext(connection) as ctx:
            delete_related_notes(finding)
        left = (
            Notes.objects.filter(id__in=note_ids).count(),
            NoteHistory.objects.filter(id__in=history_ids).count(),
        )
        self.assertEqual(left, (0, 0), f"{count} notes: notes and history rows left after the delete: {left}")
        return len(ctx.captured_queries)

    def test_query_count_does_not_grow_with_notes(self):
        few, many = self._delete(1), self._delete(10)
        self.assertEqual(few, many, f"delete_related_notes: {few} queries for 1 note, {many} for 10")

    def test_no_notes_is_one_query(self):
        finding, _, _ = self._finding_with_notes(0)
        with CaptureQueriesContext(connection) as ctx:
            delete_related_notes(finding)
        self.assertEqual(len(ctx.captured_queries), 1, [q["sql"] for q in ctx.captured_queries])

    def test_other_notes_and_their_history_are_kept(self):
        kept, kept_note_ids, kept_history_ids = self._finding_with_notes(2)
        self._delete(3)
        self.assertEqual(
            (
                Notes.objects.filter(id__in=kept_note_ids).count(),
                NoteHistory.objects.filter(id__in=kept_history_ids).count(),
            ),
            (2, 4),
        )

    def test_a_note_deleted_on_its_own_still_takes_its_history(self):
        _, note_ids, history_ids = self._finding_with_notes(1)
        Notes.objects.get(id=note_ids[0]).delete()
        self.assertEqual(NoteHistory.objects.filter(id__in=history_ids).count(), 0)
