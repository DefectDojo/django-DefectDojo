"""
Reimport reactivation: the note each reactivated finding gets, and what writing it costs.

Regression: a reimport wrote the "Re-activated by ... re-upload." note one finding at a time as it
reopened it: a note INSERT, then the m2m link's existence check and INSERT. A reimport that reopened
hundreds of findings (a container image whose findings come and go between builds) spent three
round trips per finding on the notes alone. The notes are now written once per matching batch,
through the same batched writer the close uses.
"""

import json
from datetime import datetime
from unittest.mock import patch

from crum import impersonate
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import connection
from django.db.models.signals import m2m_changed
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from dojo.importers.default_importer import DefaultImporter
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.middleware import watson_search_context_for_task
from dojo.models import Development_Environment, Engagement, Finding, Product, Product_Type, User

from .dojo_test_case import DojoTestCase

SCAN_TYPE = "Generic Findings Import"
SCAN_DATE = timezone.make_aware(datetime(2026, 1, 15, 12, 0, 0))
REACTIVATED_NOTE = f"Re-activated by {SCAN_TYPE} re-upload."


def _report(count: int) -> SimpleUploadedFile:
    findings = [
        {
            "title": f"Reactivation finding {i}",
            "severity": "High",
            "description": f"Finding number {i}",
            "unique_id_from_tool": f"reactivation-{i}",
        }
        for i in range(count)
    ]
    return SimpleUploadedFile("report.json", json.dumps({"findings": findings}).encode("utf-8"))


class TestReimportReactivationNotes(DojoTestCase):

    def setUp(self):
        super().setUp()
        self.user, _ = User.objects.get_or_create(username="admin")
        self.environment, _ = Development_Environment.objects.get_or_create(name="Development")
        self.product_type, _ = Product_Type.objects.get_or_create(name="reactivation-notes")
        self.system_settings(enable_product_grade=False)

    def _reimport(self, test, count: int) -> tuple[int, int]:
        with impersonate(self.user):
            reimporter = DefaultReImporter(
                test=test,
                user=self.user,
                lead=self.user,
                scan_date=SCAN_DATE,
                minimum_severity="Info",
                active=True,
                verified=True,
                sync=True,
                scan_type=SCAN_TYPE,
                close_old_findings=True,
            )
            _, _, _, closed, reactivated, _, _ = reimporter.process_scan(_report(count))
        return closed, reactivated

    def _closed_test(self, name: str, count: int):
        """A test with `count` + 1 findings, every one but the first closed by a reimport."""
        product = Product.objects.create(name=name, description="Test", prod_type=self.product_type)
        engagement = Engagement.objects.create(
            name=name, product=product, target_start=timezone.now(), target_end=timezone.now(),
        )
        with impersonate(self.user):
            importer = DefaultImporter(
                user=self.user,
                lead=self.user,
                scan_date=SCAN_DATE,
                environment=self.environment,
                minimum_severity="Info",
                active=True,
                verified=True,
                sync=True,
                scan_type=SCAN_TYPE,
                engagement=engagement,
            )
            test, _, _, _, _, _, _ = importer.process_scan(_report(count + 1))
        closed, _ = self._reimport(test, 1)
        self.assertEqual(count, closed, msg=f"reimport closed {closed} findings, expected {count}")
        return test

    def _note_statements(self, name: str, count: int) -> int:
        """The statements that write notes or note links while a reimport reactivates `count` findings."""
        test = self._closed_test(name, count)
        # As in a request or a Celery task: watson defers search indexing (see the close batch test).
        with watson_search_context_for_task(), CaptureQueriesContext(connection) as ctx:
            _, reactivated = self._reimport(test, count + 1)
        self.assertEqual(count, reactivated, msg=f"reimport reactivated {reactivated} findings, expected {count}")
        return sum(1 for query in ctx.captured_queries if '"dojo_notes"' in query["sql"] or '"dojo_finding_notes"' in query["sql"])

    def test_note_writes_do_not_grow_with_reactivated_count(self):
        small = self._note_statements("reactivation-small", 2)
        large = self._note_statements("reactivation-large", 6)
        self.assertEqual(
            small,
            large,
            msg=f"reactivating 2 findings wrote notes with {small} statements, reactivating 6 with {large}",
        )

    def test_each_reactivated_finding_gets_its_own_note(self):
        test = self._closed_test("reactivation-semantics", 3)
        note_adds: dict[int, set[int]] = {}

        def on_notes_changed(sender, instance, action, reverse, pk_set, **kwargs):
            if action == "post_add" and not reverse:
                note_adds.setdefault(instance.pk, set()).update(pk_set)

        m2m_changed.connect(on_notes_changed, sender=Finding.notes.through, dispatch_uid="reactivation-notes")
        try:
            _, reactivated = self._reimport(test, 4)
        finally:
            m2m_changed.disconnect(sender=Finding.notes.through, dispatch_uid="reactivation-notes")

        self.assertEqual(3, reactivated)
        reopened = Finding.objects.filter(test=test).exclude(unique_id_from_tool="reactivation-0").order_by("id")
        self.assertEqual(3, reopened.count())
        note_ids = set()
        for finding in reopened:
            with self.subTest(finding=finding.unique_id_from_tool):
                self.assertTrue(finding.active, msg=f"active={finding.active}")
                self.assertFalse(finding.is_mitigated, msg=f"is_mitigated={finding.is_mitigated}")
                notes = list(finding.notes.filter(entry=REACTIVATED_NOTE))
                self.assertEqual(
                    [(REACTIVATED_NOTE, self.user.id, False)],
                    [(n.entry, n.author_id, n.private) for n in notes],
                    msg=f"reactivation notes on finding {finding.id}",
                )
                # The note reached m2m_changed receivers, as notes.add() sent it
                self.assertIn(notes[0].id, note_adds.get(finding.id, set()), msg=f"m2m_changed post_add: {note_adds}")
                note_ids.add(notes[0].id)
        # One note per finding, never one note shared by several
        self.assertEqual(3, len(note_ids))
        self.assertEqual(0, Finding.objects.get(test=test, unique_id_from_tool="reactivation-0").notes.filter(entry=REACTIVATED_NOTE).count())

    def test_queued_notes_are_written_per_text(self):
        test = self._closed_test("reactivation-texts", 2)
        first, second = Finding.objects.filter(test=test).exclude(unique_id_from_tool="reactivation-0").order_by("id")
        reimporter = DefaultReImporter(test=test, user=self.user, scan_type=SCAN_TYPE)
        duplicate_note = f"Un-mitigated by {SCAN_TYPE} re-upload but kept inactive because the finding is a duplicate."
        reimporter.queue_reactivation_note(first, REACTIVATED_NOTE)
        reimporter.queue_reactivation_note(second, duplicate_note)
        self.assertEqual(0, Finding.notes.through.objects.filter(finding__in=[first, second], notes__entry__startswith="Un-").count())
        reimporter._flush_reactivation_notes()
        self.assertEqual([REACTIVATED_NOTE], list(first.notes.filter(entry__contains="re-upload.").exclude(entry__startswith="Mitigated").values_list("entry", flat=True)))
        self.assertEqual([duplicate_note], list(second.notes.filter(entry__startswith="Un-").values_list("entry", flat=True)))
        # Flushed once: a second flush writes nothing more
        reimporter._flush_reactivation_notes()
        self.assertEqual(1, second.notes.filter(entry__startswith="Un-").count())

    def test_a_failure_part_way_keeps_the_notes_of_findings_already_reactivated(self):
        # The notes are written at the end of a matching batch. Before, each was written with its
        # finding, so a reimport that failed part way left every finding it had reactivated with
        # its note. It still must: those findings stay reactivated.
        test = self._closed_test("reactivation-failure", 4)
        original = DefaultReImporter.process_matched_mitigated_finding
        calls = []

        def fail_on_third(reimporter, unsaved_finding, existing_finding):
            calls.append(existing_finding.pk)
            if len(calls) == 3:
                msg = "matching failed"
                raise RuntimeError(msg)
            return original(reimporter, unsaved_finding, existing_finding)

        with (
            patch.object(DefaultReImporter, "process_matched_mitigated_finding", autospec=True, side_effect=fail_on_third),
            self.assertRaisesMessage(RuntimeError, "matching failed"),
        ):
            self._reimport(test, 5)

        reopened = Finding.objects.filter(test=test, active=True, is_mitigated=False).exclude(unique_id_from_tool="reactivation-0")
        self.assertEqual(2, reopened.count(), msg=f"reactivated before the failure: {list(reopened.values_list('id', flat=True))}")
        for finding in reopened:
            with self.subTest(finding=finding.unique_id_from_tool):
                self.assertEqual(1, finding.notes.filter(entry=REACTIVATED_NOTE).count())
        still_closed = Finding.objects.filter(test=test, is_mitigated=True)
        self.assertEqual(2, still_closed.count())
        self.assertEqual(0, sum(f.notes.filter(entry=REACTIVATED_NOTE).count() for f in still_closed))
