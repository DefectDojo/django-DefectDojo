"""
Finding lifecycle provenance events: created / closed / reopened /
marked-duplicate transitions recorded by the import pipeline and dedupe,
exposed via the finding API, bounded by the retention purge task.
"""
from datetime import timedelta

from django.test import override_settings
from django.utils import timezone
from rest_framework.authtoken.models import Token

from dojo.finding.lifecycle import purge_finding_lifecycle_events
from dojo.importers.default_importer import DefaultImporter
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import (
    Development_Environment,
    Engagement,
    Finding,
    Finding_Lifecycle_Event,
    Product,
    Product_Type,
    System_Settings,
    User,
)

from .dojo_test_case import DojoAPITestCase, get_unit_tests_scans_path


class TestFindingLifecycleEvents(DojoAPITestCase):
    scan_type = "Semgrep JSON Report"

    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="admin", defaults={"is_superuser": True, "is_staff": True})
        token, _ = Token.objects.get_or_create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")

        self.environment, _ = Development_Environment.objects.get_or_create(name="Development")
        product_type, _ = Product_Type.objects.get_or_create(name="lifecycle-events")
        self.product, _ = Product.objects.get_or_create(
            name="TestLifecycleEvents",
            description="Test",
            prod_type=product_type,
        )

    def _engagement(self, name):
        engagement, _ = Engagement.objects.get_or_create(
            name=name,
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        return engagement

    def _import_options(self, engagement, scan_type=None):
        return {
            "user": self.user,
            "lead": self.user,
            "scan_date": None,
            "environment": self.environment,
            "active": True,
            "verified": False,
            "engagement": engagement,
            "scan_type": scan_type or self.scan_type,
        }

    def _events(self, finding, action=None):
        qs = Finding_Lifecycle_Event.objects.filter(finding_id=finding.id).order_by("created", "id")
        if action:
            qs = qs.filter(action=action)
        return list(qs)

    def test_full_reimport_cycle_records_created_closed_reopened(self):
        engagement = self._engagement("lifecycle reimport cycle")
        options = self._import_options(engagement)

        # run 1: finding at line 31 is created
        with (get_unit_tests_scans_path("semgrep") / "close_old_findings_report_line31.json").open(encoding="utf-8") as scan:
            importer = DefaultImporter(close_old_findings=False, **options)
            test, _, len_new, _, _, _, _ = importer.process_scan(scan, force_sync=True)
        self.assertEqual(1, len_new)
        original = Finding.objects.filter(test=test).order_by("id").first()

        created_events = self._events(original, Finding_Lifecycle_Event.Action.CREATED)
        self.assertEqual(1, len(created_events))
        self.assertEqual("import", created_events[0].detail["kind"])
        self.assertEqual(test.id, created_events[0].detail["test_id"])
        self.assertEqual(Finding_Lifecycle_Event.ActorType.IMPORT, created_events[0].actor_type)

        reimport_options = {
            "test": test,
            "user": self.user,
            "lead": self.user,
            "scan_date": None,
            "minimum_severity": "Info",
            "active": True,
            "verified": False,
            "scan_type": self.scan_type,
            "close_old_findings": True,
        }

        # run 2: the flaw moved to line 24 but semgrep's fingerprint is stable —
        # the reimport MATCHES the existing finding. Transition-only discipline:
        # an unchanged match must produce zero new lifecycle events.
        with (get_unit_tests_scans_path("semgrep") / "close_old_findings_report_second_run_line24.json").open(encoding="utf-8") as scan:
            reimporter = DefaultReImporter(**reimport_options)
            test, _, _, len_closed, _, _, _ = reimporter.process_scan(scan, force_sync=True)
        self.assertEqual(0, len_closed)
        self.assertEqual(1, len(self._events(original)), "matched-unchanged reimport must not write events")

        # run 3: the tool now reports a different unique id — the old finding
        # no longer matches, so it closes and a new finding is created
        with (get_unit_tests_scans_path("semgrep") / "close_old_findings_report_third_run_different_unique_id.json").open(encoding="utf-8") as scan:
            reimporter = DefaultReImporter(**reimport_options)
            test, _, _, len_closed, _, _, _ = reimporter.process_scan(scan, force_sync=True)
        self.assertEqual(1, len_closed)

        closed_events = self._events(original, Finding_Lifecycle_Event.Action.CLOSED)
        self.assertEqual(1, len(closed_events))
        self.assertIn("reason", closed_events[0].detail)
        self.assertEqual(test.id, closed_events[0].detail["test_id"])

        new_finding = Finding.objects.filter(test=test).exclude(id=original.id).order_by("-id").first()
        self.assertIsNotNone(new_finding)
        new_created = self._events(new_finding, Finding_Lifecycle_Event.Action.CREATED)
        self.assertEqual(1, len(new_created))
        self.assertEqual("reimport", new_created[0].detail["kind"])

        # run 4: the original fingerprint reappears — the closed finding reactivates
        with (get_unit_tests_scans_path("semgrep") / "close_old_findings_report_line31.json").open(encoding="utf-8") as scan:
            reimporter = DefaultReImporter(**reimport_options)
            reimporter.process_scan(scan, force_sync=True)

        reopened_events = self._events(original, Finding_Lifecycle_Event.Action.REOPENED)
        self.assertEqual(1, len(reopened_events))
        self.assertIn("reason", reopened_events[0].detail)

    def test_dedupe_records_marked_duplicate_with_original(self):
        system_settings = System_Settings.objects.get()
        system_settings.enable_deduplication = True
        system_settings.save()
        try:
            engagement = self._engagement("lifecycle dedupe")
            engagement.deduplication_on_engagement = True
            engagement.save()
            options = self._import_options(engagement, scan_type="Acunetix Scan")

            with (get_unit_tests_scans_path("acunetix") / "one_finding.xml").open(encoding="utf-8") as scan:
                importer = DefaultImporter(close_old_findings=False, **options)
                _test1, _, _, _, _, _, _ = importer.process_scan(scan, force_sync=True)
            with (get_unit_tests_scans_path("acunetix") / "one_finding.xml").open(encoding="utf-8") as scan:
                importer = DefaultImporter(close_old_findings=False, **options)
                test2, _, _, _, _, _, _ = importer.process_scan(scan, force_sync=True)

            duplicate = Finding.objects.filter(test=test2, duplicate=True).first()
            self.assertIsNotNone(duplicate, "second import of the same report should produce a duplicate")

            dup_events = self._events(duplicate, Finding_Lifecycle_Event.Action.MARKED_DUPLICATE)
            self.assertEqual(1, len(dup_events))
            self.assertEqual(Finding_Lifecycle_Event.ActorType.DEDUPE, dup_events[0].actor_type)
            self.assertEqual(duplicate.duplicate_finding_id, dup_events[0].detail["original_id"])
        finally:
            system_settings.enable_deduplication = False
            system_settings.save()

    def test_lifecycle_events_api_endpoint(self):
        engagement = self._engagement("lifecycle api")
        options = self._import_options(engagement)
        with (get_unit_tests_scans_path("semgrep") / "close_old_findings_report_line31.json").open(encoding="utf-8") as scan:
            importer = DefaultImporter(close_old_findings=False, **options)
            test, _, _, _, _, _, _ = importer.process_scan(scan, force_sync=True)
        finding = Finding.objects.filter(test=test).first()

        response = self.client.get(f"/api/v2/findings/{finding.id}/lifecycle_events/", format="json")
        self.assertEqual(200, response.status_code, response.content)
        data = response.json()
        self.assertTrue(data)
        self.assertEqual("created", data[-1]["action"])  # newest first
        self.assertEqual("import", data[-1]["detail"]["kind"])

    def test_purge_respects_retention_window(self):
        engagement = self._engagement("lifecycle purge")
        options = self._import_options(engagement)
        with (get_unit_tests_scans_path("semgrep") / "close_old_findings_report_line31.json").open(encoding="utf-8") as scan:
            importer = DefaultImporter(close_old_findings=False, **options)
            importer.process_scan(scan, force_sync=True)

        total_before = Finding_Lifecycle_Event.objects.count()
        self.assertGreater(total_before, 0)

        # nothing is old enough: purge deletes nothing
        self.assertEqual(0, purge_finding_lifecycle_events())

        # backdate everything past the retention window: purge removes it all
        Finding_Lifecycle_Event.objects.update(created=timezone.now() - timedelta(days=9999))
        self.assertEqual(total_before, purge_finding_lifecycle_events())
        self.assertEqual(0, Finding_Lifecycle_Event.objects.count())

    @override_settings(FINDING_LIFECYCLE_EVENTS_ENABLED=False)
    def test_kill_switch_disables_event_writes(self):
        engagement = self._engagement("lifecycle disabled")
        options = self._import_options(engagement)
        with (get_unit_tests_scans_path("semgrep") / "close_old_findings_report_line31.json").open(encoding="utf-8") as scan:
            importer = DefaultImporter(close_old_findings=False, **options)
            importer.process_scan(scan, force_sync=True)
        self.assertEqual(0, Finding_Lifecycle_Event.objects.count())
