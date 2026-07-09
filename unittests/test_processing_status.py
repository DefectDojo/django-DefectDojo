import logging
from unittest.mock import patch

from django.test import override_settings
from django.utils import timezone

from dojo.finding import helper as finding_helper
from dojo.importers.default_importer import DefaultImporter
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.jira import helper as jira_helper
from dojo.models import Development_Environment, Engagement, Finding, Finding_Group, Product, Product_Type, User

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


class TestJiraPushProcessingStatus(DojoTestCase):

    """
    The JIRA helpers swallow errors and report them as a (success, message)
    tuple, so a failed push never raises. The push tasks are the writer of
    record for that outcome: failures stamp the finding(s) FAILED with the
    helper's message, later successful pushes heal FAILED back to PROCESSED,
    and the batch stamp never overwrites a FAILED stamped inline (eager
    execution) because its final UPDATE excludes FAILED rows.
    """

    scan_type = "Acunetix Scan"

    def setUp(self):
        user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="processing-status-jira")
        environment, _ = Development_Environment.objects.get_or_create(name="Development")
        product, _ = Product.objects.get_or_create(
            name="TestJiraPushProcessingStatus",
            description="Test",
            prod_type=product_type,
        )
        engagement, _ = Engagement.objects.get_or_create(
            name="processing status jira",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        options = {
            "user": user,
            "lead": user,
            "scan_date": None,
            "environment": environment,
            "active": True,
            "verified": False,
            "engagement": engagement,
            "scan_type": self.scan_type,
        }
        with (get_unit_tests_scans_path("acunetix") / "many_findings.xml").open(encoding="utf-8") as scan:
            importer = DefaultImporter(close_old_findings=False, **options)
            self.test, _, _, _, _, _, _ = importer.process_scan(scan, force_sync=True)
        self.user = user
        self.findings = list(Finding.objects.filter(test=self.test).order_by("id"))
        self.finding = self.findings[0]

    @patch("dojo.jira.helper.add_jira_issue", return_value=(False, "The Jira instance rejected the credentials."))
    def test_failed_push_stamps_finding_failed_with_reason(self, mock_add):
        jira_helper.push_finding_to_jira(self.finding.id)

        self.finding.refresh_from_db()
        self.assertEqual(Finding.ProcessingStatus.FAILED, self.finding.processing_status)
        self.assertEqual("The Jira instance rejected the credentials.", self.finding.processing_error)

    @patch("dojo.jira.helper.add_jira_issue", return_value=(True, "ticket created"))
    def test_successful_push_heals_a_failed_finding(self, mock_add):
        Finding.objects.filter(id=self.finding.id).update(
            processing_status=Finding.ProcessingStatus.FAILED,
            processing_error="previous push failure",
        )

        jira_helper.push_finding_to_jira(self.finding.id)

        self.finding.refresh_from_db()
        self.assertEqual(Finding.ProcessingStatus.PROCESSED, self.finding.processing_status)
        self.assertEqual("", self.finding.processing_error)

    @patch("dojo.jira.helper.add_jira_issue", return_value=(True, "ticket created"))
    def test_successful_push_leaves_non_failed_findings_alone(self, mock_add):
        Finding.objects.filter(id=self.finding.id).update(
            processing_status=Finding.ProcessingStatus.PENDING,
            processed_at=None,
        )

        jira_helper.push_finding_to_jira(self.finding.id)

        self.finding.refresh_from_db()
        # the batch owns the happy-path stamp; a successful push must not skip a PENDING finding ahead
        self.assertEqual(Finding.ProcessingStatus.PENDING, self.finding.processing_status)

    @patch("dojo.jira.helper.add_jira_issue", return_value=(False, "group push exploded"))
    def test_failed_group_push_fans_out_to_member_findings(self, mock_add):
        group = Finding_Group.objects.create(name="jira group", test=self.test, creator=self.user)
        members = self.findings[:2]
        group.findings.set(members)

        jira_helper.push_finding_group_to_jira(group.id)

        for finding in Finding.objects.filter(id__in=[f.id for f in members]):
            self.assertEqual(Finding.ProcessingStatus.FAILED, finding.processing_status)
            self.assertEqual("group push exploded", finding.processing_error)
        # non-members are untouched
        outsider = Finding.objects.get(id=self.findings[2].id)
        self.assertEqual(Finding.ProcessingStatus.PROCESSED, outsider.processing_status)

    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    @patch("dojo.jira.helper.add_jira_issue", return_value=(False, "eager push failure"))
    def test_batch_stamp_does_not_overwrite_inline_push_failure(self, mock_add):
        # In eager execution the push runs inside the batch's try block, so the
        # batch's final UPDATE runs *after* the failure was stamped — it must
        # leave FAILED rows alone instead of flipping them back to PROCESSED.
        finding_ids = [f.id for f in self.findings]
        Finding.objects.filter(id__in=finding_ids).update(
            processing_status=Finding.ProcessingStatus.PENDING,
        )

        finding_helper.post_process_findings_batch(
            finding_ids,
            dedupe_option=False,
            issue_updater_option=False,
            product_grading_option=False,
            push_to_jira=True,
        )

        statuses = {f.id: (f.processing_status, f.processing_error) for f in Finding.objects.filter(id__in=finding_ids)}
        for status, error in statuses.values():
            self.assertEqual(Finding.ProcessingStatus.FAILED, status)
            self.assertEqual("eager push failure", error)

    def test_batch_failure_records_the_reason(self):
        finding_ids = [f.id for f in self.findings]
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
            self.assertEqual("simulated post-processing crash", finding.processing_error)
