"""
Reimport close_old_findings: query cost and semantics of closing many findings.

Regression: a reimport paid about a dozen queries for every finding it closed, because
close_old_findings mitigated them one at a time (a note insert plus its m2m add, an
endpoint status lookup, a JIRA issue lookup, a full Finding.save() and its synchronous
post-processing). On a large test that dominated the reimport.
"""

import json
from datetime import datetime

from crum import impersonate
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import connection
from django.db.models.signals import m2m_changed, post_save
from django.test.utils import CaptureQueriesContext, override_settings
from django.utils import timezone

from dojo.importers.default_importer import DefaultImporter
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.location.models import LocationFindingReference
from dojo.location.status import FindingLocationStatus
from dojo.middleware import watson_search_context_for_task
from dojo.models import (
    Development_Environment,
    Endpoint_Status,
    Engagement,
    Finding,
    Product,
    Product_Type,
    User,
)

from .dojo_test_case import DojoTestCase

SCAN_TYPE = "Generic Findings Import"
SCAN_DATE = timezone.make_aware(datetime(2026, 1, 15, 12, 0, 0))


def _report(count: int) -> SimpleUploadedFile:
    """A generic JSON report with `count` distinct findings, each on its own endpoint and file."""
    findings = [
        {
            "title": f"Close batch finding {i}",
            "severity": "High",
            "description": f"Finding number {i}",
            "file_path": f"src/module_{i}.py",
            "unique_id_from_tool": f"close-batch-{i}",
            "endpoints": [f"https://host{i}.example.com/path"],
        }
        for i in range(count)
    ]
    return SimpleUploadedFile("report.json", json.dumps({"findings": findings}).encode("utf-8"))


class CloseOldFindingsBatchMixin:

    def setUp(self):
        super().setUp()
        self.user, _ = User.objects.get_or_create(username="admin")
        self.environment, _ = Development_Environment.objects.get_or_create(name="Development")
        self.product_type, _ = Product_Type.objects.get_or_create(name="close-batch")
        self.system_settings(enable_product_grade=False)
        self.system_settings(enable_deduplication=True)

    def _seed_test(self, name: str, count: int):
        """Import `count` findings into a fresh product and return the resulting test."""
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
            test, _, new, _, _, _, _ = importer.process_scan(_report(count))
        self.assertEqual(count, new, msg=f"seed import created {new} findings, expected {count}")
        return test

    def _reimport_keeping_one(self, test):
        """Reimport a report that only still reports finding 0, so every other finding is closed."""
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
            _, _, _, closed, _, _, _ = reimporter.process_scan(_report(1))
        return closed

    def _closing_cost(self, name: str, to_close: int) -> int:
        test = self._seed_test(name, to_close + 1)
        # A request or a Celery task always runs inside a watson search context, which
        # defers search indexing to batched async tasks. Without one, watson re-indexes
        # every saved finding inline, which is a cost of the test harness, not the reimport.
        with watson_search_context_for_task(), CaptureQueriesContext(connection) as ctx:
            closed = self._reimport_keeping_one(test)
        self.assertEqual(to_close, closed, msg=f"reimport closed {closed} findings, expected {to_close}")
        return len(ctx.captured_queries)

    def test_closing_cost_does_not_grow_with_closed_count(self):
        small = 4
        cost_small = self._closing_cost("close-batch-small", small)
        cost_large = self._closing_cost("close-batch-large", small * 2)
        # Allow a small constant (a cache warming differently, a chunk boundary), never a
        # per-finding cost: before batching this grew by about a dozen queries per finding.
        self.assertLessEqual(
            cost_large - cost_small,
            3,
            msg=(
                f"closing {small} findings took {cost_small} queries, closing {small * 2} took "
                f"{cost_large}: {(cost_large - cost_small) / small:.1f} extra queries per closed finding"
            ),
        )

    def test_closed_findings_match_per_finding_semantics(self):
        test = self._seed_test("close-batch-semantics", 4)
        kept = Finding.objects.get(test=test, unique_id_from_tool="close-batch-0")

        note_adds: dict[int, set[int]] = {}
        saved_ids: list[int] = []

        def on_notes_changed(sender, instance, action, reverse, pk_set, **kwargs):
            if action == "post_add" and not reverse:
                note_adds.setdefault(instance.pk, set()).update(pk_set)

        def on_finding_saved(sender, instance, created, **kwargs):
            if not created:
                saved_ids.append(instance.pk)

        m2m_changed.connect(on_notes_changed, sender=Finding.notes.through, dispatch_uid="close-batch-notes")
        post_save.connect(on_finding_saved, sender=Finding, dispatch_uid="close-batch-saves")
        try:
            closed = self._reimport_keeping_one(test)
        finally:
            m2m_changed.disconnect(sender=Finding.notes.through, dispatch_uid="close-batch-notes")
            post_save.disconnect(sender=Finding, dispatch_uid="close-batch-saves")

        self.assertEqual(3, closed)
        closed_findings = list(Finding.objects.filter(test=test).exclude(id=kept.id).order_by("id"))
        self.assertEqual(3, len(closed_findings))
        expected_note = f"Mitigated by {test.test_type} re-upload."
        for finding in closed_findings:
            with self.subTest(finding=finding.unique_id_from_tool):
                self.assertFalse(finding.active, msg=f"active={finding.active}")
                self.assertTrue(finding.is_mitigated, msg=f"is_mitigated={finding.is_mitigated}")
                self.assertEqual(SCAN_DATE, finding.mitigated, msg=f"mitigated={finding.mitigated}")
                self.assertEqual(self.user, finding.mitigated_by, msg=f"mitigated_by={finding.mitigated_by}")
                self.assertIsNotNone(finding.last_status_update)
                # save() keeps static/dynamic in step with file_path and locations
                self.assertTrue(finding.static_finding)
                notes = list(finding.notes.all())
                self.assertEqual(
                    [(expected_note, self.user.id, False)],
                    [(n.entry, n.author_id, n.private) for n in notes],
                    msg=f"notes on finding {finding.id}: {[(n.entry, n.author_id) for n in notes]}",
                )
                # The note reached m2m_changed receivers, and the finding reached post_save receivers
                self.assertEqual({notes[0].id}, note_adds.get(finding.id), msg=f"m2m_changed post_add: {note_adds}")
                self.assertIn(finding.id, saved_ids, msg=f"post_save(created=False) ids: {saved_ids}")
                if self.locations_mode:
                    statuses = list(LocationFindingReference.objects.filter(finding=finding))
                    self.assertTrue(statuses)
                    for ref in statuses:
                        self.assertEqual(FindingLocationStatus.Mitigated, ref.status, msg=f"location status={ref.status}")
                        self.assertEqual(self.user, ref.auditor, msg=f"auditor={ref.auditor}")
                else:
                    statuses = list(Endpoint_Status.objects.filter(finding=finding))
                    self.assertEqual(1, len(statuses))
                    for status in statuses:
                        self.assertTrue(status.mitigated, msg=f"endpoint status mitigated={status.mitigated}")
                        self.assertEqual(self.user, status.mitigated_by, msg=f"mitigated_by={status.mitigated_by}")
                        self.assertIsNotNone(status.mitigated_time)

        kept.refresh_from_db()
        self.assertTrue(kept.active, msg=f"kept finding active={kept.active}")
        self.assertFalse(kept.is_mitigated)
        self.assertEqual(0, kept.notes.count())

    def test_a_receiver_failing_mid_batch_leaves_nothing_half_closed(self):
        # The old per-finding path saved and post-processed each finding together, so a
        # failure left the rest open and the next reimport closed them. The batched close must
        # not leave findings written as closed whose post_save never ran: the next reimport
        # would skip them as already mitigated.
        test = self._seed_test("close-batch-failure", 4)
        kept = Finding.objects.get(test=test, unique_id_from_tool="close-batch-0")
        calls = []

        def fail_on_second(sender, instance, created, **kwargs):
            if not created:
                calls.append(instance.pk)
                if len(calls) == 2:
                    msg = "receiver failed"
                    raise RuntimeError(msg)

        post_save.connect(fail_on_second, sender=Finding, dispatch_uid="close-batch-fail")
        try:
            with self.assertRaises(RuntimeError):
                self._reimport_keeping_one(test)
        finally:
            post_save.disconnect(sender=Finding, dispatch_uid="close-batch-fail")

        others = Finding.objects.filter(test=test).exclude(id=kept.id)
        with self.subTest("nothing was written closed"):
            self.assertEqual(3, others.filter(active=True, is_mitigated=False).count())
        with self.subTest("no close notes were left behind"):
            self.assertEqual(0, sum(finding.notes.count() for finding in others))
        with self.subTest("the next reimport closes them"):
            self.assertEqual(3, self._reimport_keeping_one(test))
            self.assertEqual(3, others.filter(active=False, is_mitigated=True).count())


@override_settings(V3_FEATURE_LOCATIONS=False)
class TestReimportCloseOldFindingsBatchEndpoints(CloseOldFindingsBatchMixin, DojoTestCase):
    locations_mode = False


@override_settings(V3_FEATURE_LOCATIONS=True)
class TestReimportCloseOldFindingsBatchLocations(CloseOldFindingsBatchMixin, DojoTestCase):
    locations_mode = True
