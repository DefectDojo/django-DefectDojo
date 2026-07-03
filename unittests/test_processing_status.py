import logging
from unittest.mock import patch

from django.utils import timezone

from dojo.finding import helper as finding_helper
from dojo.importers.default_importer import DefaultImporter
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import Development_Environment, Engagement, Finding, Product, Product_Type, User

from .dojo_test_case import DojoTestCase, get_unit_tests_scans_path

logger = logging.getLogger(__name__)


class TestProcessingStatus(DojoTestCase):

    """
    The post-import processing lifecycle on findings.

    Imported findings are created PENDING and stamped PROCESSED (or FAILED)
    by post_process_findings_batch when the pipeline completes. Findings
    created outside the import pipeline default to PROCESSED and never
    enter PENDING.
    """

    scan_type = "Acunetix Scan"

    def _import_options(self, engagement_name):
        user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="processing-status")
        environment, _ = Development_Environment.objects.get_or_create(name="Development")
        product, _ = Product.objects.get_or_create(
            name="TestProcessingStatus",
            description="Test",
            prod_type=product_type,
        )
        engagement, _ = Engagement.objects.get_or_create(
            name=engagement_name,
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        return {
            "user": user,
            "lead": user,
            "scan_date": None,
            "environment": environment,
            "active": True,
            "verified": False,
            "engagement": engagement,
            "scan_type": self.scan_type,
        }

    def _import_scan(self, options, filename="many_findings.xml"):
        with (get_unit_tests_scans_path("acunetix") / filename).open(encoding="utf-8") as scan:
            importer = DefaultImporter(close_old_findings=False, **options)
            # force_sync so post_process_findings_batch runs inline (no celery worker in unit tests)
            test, _, len_new_findings, _, _, _, _ = importer.process_scan(scan, force_sync=True)
        return test, len_new_findings

    def test_imported_findings_are_stamped_processed(self):
        test, len_new_findings = self._import_scan(self._import_options("processing status import"))
        self.assertEqual(4, len_new_findings)
        findings = Finding.objects.filter(test=test)
        self.assertEqual(4, findings.count())
        for finding in findings:
            self.assertEqual(Finding.ProcessingStatus.PROCESSED, finding.processing_status)
            self.assertIsNotNone(finding.processed_at)

    def test_reimport_restamps_matched_findings(self):
        options = self._import_options("processing status reimport")
        test, _ = self._import_scan(options)
        first_pass = dict(Finding.objects.filter(test=test).values_list("id", "processed_at"))
        self.assertTrue(all(first_pass.values()))

        reimport_options = {
            "test": test,
            "user": options["user"],
            "lead": options["lead"],
            "scan_date": None,
            "minimum_severity": "Info",
            "active": True,
            "verified": False,
            "scan_type": self.scan_type,
        }
        with (get_unit_tests_scans_path("acunetix") / "many_findings.xml").open(encoding="utf-8") as scan:
            reimporter = DefaultReImporter(**reimport_options)
            test, _, _, _, _, _, _ = reimporter.process_scan(scan, force_sync=True)

        findings = Finding.objects.filter(test=test)
        self.assertGreater(findings.count(), 0)
        for finding in findings:
            self.assertEqual(Finding.ProcessingStatus.PROCESSED, finding.processing_status)
            self.assertIsNotNone(finding.processed_at)
            # matched findings never re-enter PENDING; they get a refreshed stamp
            if finding.id in first_pass:
                self.assertGreaterEqual(finding.processed_at, first_pass[finding.id])

    def test_failed_batch_is_stamped_failed(self):
        test, _ = self._import_scan(self._import_options("processing status failure"))
        finding_ids = list(Finding.objects.filter(test=test).values_list("id", flat=True))
        self.assertTrue(finding_ids)

        with patch(
            "dojo.finding.helper.tool_issue_updater.async_tool_issue_update",
            side_effect=RuntimeError("simulated post-processing crash"),
        ), self.assertRaises(RuntimeError):
            finding_helper.post_process_findings_batch(
                finding_ids,
                dedupe_option=False,
                issue_updater_option=True,
                product_grading_option=False,
                push_to_jira=False,
            )

        for finding in Finding.objects.filter(id__in=finding_ids):
            self.assertEqual(Finding.ProcessingStatus.FAILED, finding.processing_status)
            self.assertIsNotNone(finding.processed_at)

    def test_manual_finding_defaults_to_processed(self):
        options = self._import_options("processing status manual")
        test, _ = self._import_scan(options)
        finding = Finding(
            test=test,
            title="manually entered finding",
            severity="Low",
            description="entered by hand, never enters the import pipeline",
            reporter=options["user"],
        )
        finding.save_no_options()
        finding.refresh_from_db()
        self.assertEqual(Finding.ProcessingStatus.PROCESSED, finding.processing_status)
        self.assertIsNone(finding.processed_at)
