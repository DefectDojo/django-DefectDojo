import logging
from unittest import mock

from django.utils import timezone

import dojo.risk_acceptance.helper as ra_helper
from dojo.importers.default_importer import DefaultImporter
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import Development_Environment, Engagement, Finding, Product, Product_Type, User

from .dojo_test_case import DojoTestCase, get_unit_tests_scans_path

logger = logging.getLogger(__name__)


class TestDojoCloseOld(DojoTestCase):
    # Regression: close_old_findings fetched every Finding column (incl. description) via
    # findings.values() just to collect is_mitigated/hash_code/unique_id_from_tool.
    def test_close_old_findings_only_fetches_needed_columns(self):
        scan_type = "Acunetix Scan"
        user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="closeold")
        environment, _ = Development_Environment.objects.get_or_create(name="Development")
        product, _ = Product.objects.get_or_create(
            name="TestDojoCloseOldColumns",
            description="Test",
            prod_type=product_type,
        )
        engagement, _ = Engagement.objects.get_or_create(
            name="Close Old Needed Columns",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        import_options = {
            "user": user,
            "lead": user,
            "scan_date": None,
            "environment": environment,
            "active": True,
            "verified": False,
            "engagement": engagement,
            "scan_type": scan_type,
        }
        # Seed an older test with 4 findings that the close-old pass should mitigate
        with (get_unit_tests_scans_path("acunetix") / "many_findings.xml").open(encoding="utf-8") as many_findings_scan:
            importer = DefaultImporter(close_old_findings=False, **import_options)
            _, _, len_new_findings, _, _, _, _ = importer.process_scan(many_findings_scan)
            self.assertEqual(4, len_new_findings)
        # Import a report with a single finding, without closing, to get the new test
        with (get_unit_tests_scans_path("acunetix") / "one_finding.xml").open(encoding="utf-8") as single_finding_scan:
            importer = DefaultImporter(close_old_findings=False, **import_options)
            test, _, len_new_findings, _, _, _, _ = importer.process_scan(single_finding_scan)
            self.assertEqual(1, len_new_findings)
        # Call close_old_findings directly with the new test's queryset and spy on values()
        importer = DefaultImporter(close_old_findings=True, **import_options)
        importer.test = test
        findings_queryset = test.finding_set.all()
        with mock.patch.object(findings_queryset, "values", wraps=findings_queryset.values) as values_spy:
            closed_findings = importer.close_old_findings(findings_queryset)
        values_spy.assert_called_once_with(
            "is_mitigated", "hash_code", "unique_id_from_tool",
        )
        # Control: narrowing the columns must not change which findings get closed
        # (the 4 findings from the older test; dedupe is off, so the overlapping
        # finding closes too — same semantics as test_close_old_same_engagement)
        self.assertEqual(
            4, len(closed_findings),
            msg=f"expected 4 old findings closed, got {len(closed_findings)}",
        )

    def test_close_old_same_engagement(self):
        scan_type = "Acunetix Scan"
        user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="closeold")
        environment, _ = Development_Environment.objects.get_or_create(name="Development")
        product, _ = Product.objects.get_or_create(
            name="TestDojoCloseOldImporter1",
            description="Test",
            prod_type=product_type,
        )
        engagement, _ = Engagement.objects.get_or_create(
            name="Close Old Same Engagement",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        import_options = {
            "user": user,
            "lead": user,
            "scan_date": None,
            "environment": environment,
            "active": True,
            "verified": False,
            "engagement": engagement,
            "scan_type": scan_type,
        }
        # Import first test
        with (get_unit_tests_scans_path("acunetix") / "many_findings.xml").open(encoding="utf-8") as many_findings_scan:
            importer = DefaultImporter(close_old_findings=False, **import_options)
            _, _, len_new_findings, len_closed_findings, _, _, _ = importer.process_scan(many_findings_scan)
            self.assertEqual(4, len_new_findings)
            self.assertEqual(0, len_closed_findings)
        # Import same test, should close no findings
        with (get_unit_tests_scans_path("acunetix") / "many_findings.xml").open(encoding="utf-8") as many_findings_scan:
            importer = DefaultImporter(close_old_findings=True, **import_options)
            _, _, len_new_findings, len_closed_findings, _, _, _ = importer.process_scan(many_findings_scan)
            self.assertEqual(4, len_new_findings)
            self.assertEqual(0, len_closed_findings)
        # Import test with only one finding. Remaining findings should close
        with (get_unit_tests_scans_path("acunetix") / "one_finding.xml").open(encoding="utf-8") as single_finding_scan:
            importer = DefaultImporter(close_old_findings=True, **import_options)
            _, _, len_new_findings, len_closed_findings, _, _, _ = importer.process_scan(single_finding_scan)
            self.assertEqual(1, len_new_findings)
            # Dedupe is off and close old findings does not close old findings if they are the same finding.
            # If this behavior changes, or dedupe is on, the number of closed findings will be 4
            self.assertEqual(8, len_closed_findings)

    def test_close_old_same_product_scan(self):
        scan_type = "Acunetix Scan"
        user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="test2")
        product, _ = Product.objects.get_or_create(
            name="TestDojoCloseOldImporter2",
            description="Test",
            prod_type=product_type,
        )
        engagement1, _ = Engagement.objects.get_or_create(
            name="Close Old Same Product 1",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        engagement2, _ = Engagement.objects.get_or_create(
            name="Close Old Same Product 2",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        engagement3, _ = Engagement.objects.get_or_create(
            name="Close Old Same Product 3",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        environment, _ = Development_Environment.objects.get_or_create(name="Development")
        import_options = {
            "user": user,
            "lead": user,
            "scan_date": None,
            "environment": environment,
            "active": True,
            "verified": False,
            "close_old_findings_product_scope": True,
            "scan_type": scan_type,
        }
        # Import first test
        with (get_unit_tests_scans_path("acunetix") / "many_findings.xml").open(encoding="utf-8") as many_findings_scan:
            importer = DefaultImporter(engagement=engagement1, close_old_findings=False, **import_options)
            _, _, len_new_findings, len_closed_findings, _, _, _ = importer.process_scan(many_findings_scan)
            self.assertEqual(4, len_new_findings)
            self.assertEqual(0, len_closed_findings)
        # Import same test, should close no findings
        with (get_unit_tests_scans_path("acunetix") / "many_findings.xml").open(encoding="utf-8") as many_findings_scan:
            importer = DefaultImporter(engagement=engagement2, close_old_findings=True, **import_options)
            _, _, len_new_findings, len_closed_findings, _, _, _ = importer.process_scan(many_findings_scan)
            self.assertEqual(4, len_new_findings)
            self.assertEqual(0, len_closed_findings)
        # Import test with only one finding. Remaining findings should close
        with (get_unit_tests_scans_path("acunetix") / "one_finding.xml").open(encoding="utf-8") as single_finding_scan:
            importer = DefaultImporter(engagement=engagement3, close_old_findings=True, **import_options)
            _, _, len_new_findings, len_closed_findings, _, _, _ = importer.process_scan(single_finding_scan)
            self.assertEqual(1, len_new_findings)
            # Dedupe is off, and close old findings does not close old findings if they are the same finding.
            # If this behavior changes, or dedupe is on, the number of closed findings will be 4
            self.assertEqual(8, len_closed_findings)

    def test_close_old_same_product_scan_matching_with_unique_id_from_tool(self):
        scan_type = "Semgrep JSON Report"
        user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="test2")
        product, _ = Product.objects.get_or_create(
            name="TestDojoCloseOldImporter3",
            description="Test",
            prod_type=product_type,
        )
        engagement1, _ = Engagement.objects.get_or_create(
            name="Close Old Same Product 1",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        engagement2, _ = Engagement.objects.get_or_create(
            name="Close Old Same Product 2",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        engagement3, _ = Engagement.objects.get_or_create(
            name="Close Old Same Product 3",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        environment, _ = Development_Environment.objects.get_or_create(name="Development")
        import_options = {
            "user": user,
            "lead": user,
            "scan_date": None,
            "environment": environment,
            "active": True,
            "verified": False,
            "close_old_findings_product_scope": True,
            "scan_type": scan_type,
        }
        # Import first test
        with (get_unit_tests_scans_path("semgrep") / "close_old_findings_report_line31.json").open(encoding="utf-8") as many_findings_scan:
            importer = DefaultImporter(engagement=engagement1, close_old_findings=False, **import_options)
            _, _, len_new_findings, len_closed_findings, _, _, _ = importer.process_scan(many_findings_scan)
            self.assertEqual(1, len_new_findings)
            self.assertEqual(0, len_closed_findings)
        # Import separate report with different line number. Before this change, the legacy dedupe algorithm would calculate a different
        # hash code and close of the findings. Now that we are matching on unique ID from tool, we should no close anything, and create one
        with (get_unit_tests_scans_path("semgrep") / "close_old_findings_report_second_run_line24.json").open(encoding="utf-8") as many_findings_scan:
            importer = DefaultImporter(engagement=engagement2, close_old_findings=True, **import_options)
            _, _, len_new_findings, len_closed_findings, _, _, _ = importer.process_scan(many_findings_scan)
            self.assertEqual(1, len_new_findings)
            self.assertEqual(0, len_closed_findings)
        # This scan has a different unique ID from tool, so we should have one new finding, and one closed finding
        with (get_unit_tests_scans_path("semgrep") / "close_old_findings_report_third_run_different_unique_id.json").open(encoding="utf-8") as many_findings_scan:
            importer = DefaultImporter(engagement=engagement3, close_old_findings=True, **import_options)
            _, _, len_new_findings, len_closed_findings, _, _, _ = importer.process_scan(many_findings_scan)
            self.assertEqual(1, len_new_findings)
            self.assertEqual(1, len_closed_findings)

    def test_close_old_closes_risk_accepted_findings(self):
        """Test that close_old_findings closes risk-accepted findings when not in new scan"""
        scan_type = "Acunetix Scan"
        user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="closeold_risk")
        product, _ = Product.objects.get_or_create(
            name="TestCloseOldRiskAccepted",
            description="Test",
            prod_type=product_type,
        )
        product.enable_simple_risk_acceptance = True
        product.save()

        engagement, _ = Engagement.objects.get_or_create(
            name="Close Old Risk Accepted",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        environment, _ = Development_Environment.objects.get_or_create(name="Development")
        import_options = {
            "user": user,
            "lead": user,
            "scan_date": None,
            "environment": environment,
            "active": True,
            "verified": False,
            "engagement": engagement,
            "scan_type": scan_type,
        }

        # Import many findings
        with (get_unit_tests_scans_path("acunetix") / "many_findings.xml").open(encoding="utf-8") as scan:
            importer = DefaultImporter(close_old_findings=False, **import_options)
            test, _, len_new, len_closed, _, _, _ = importer.process_scan(scan)
            self.assertEqual(4, len_new)
            self.assertEqual(0, len_closed)

        # Risk accept one finding
        finding_to_accept = test.finding_set.first()
        ra_helper.simple_risk_accept(user, finding_to_accept)
        finding_to_accept.refresh_from_db()
        self.assertTrue(finding_to_accept.risk_accepted)
        self.assertFalse(finding_to_accept.active)

        # Import scan with only one finding (different from risk-accepted one)
        # close_old_findings should close the risk-accepted finding
        with (get_unit_tests_scans_path("acunetix") / "one_finding.xml").open(encoding="utf-8") as scan:
            importer = DefaultImporter(close_old_findings=True, **import_options)
            _, _, len_new, len_closed, _, _, _ = importer.process_scan(scan)
            self.assertEqual(1, len_new)
            # At least 3 findings should be closed (including the risk-accepted one)
            # The exact number depends on deduplication, but we verify below
            self.assertGreaterEqual(len_closed, 3)

        # Verify risk-accepted finding was closed
        finding_to_accept.refresh_from_db()
        self.assertTrue(finding_to_accept.is_mitigated, "Risk-accepted finding should be mitigated when vulnerability is fixed")
        self.assertFalse(finding_to_accept.risk_accepted, "Risk acceptance should be removed when vulnerability is fixed")


class TestReimportCloseOldVanishedFindings(DojoTestCase):

    """
    Regression: a close-old candidate whose row disappears mid-reimport must be skipped.

    close_old_findings collects its candidates while processing the report and only then
    refreshes their status fields from the database. A finding deleted in between (for
    example by a concurrent bulk delete of mitigated findings) has no row left to refresh,
    and the refresh fell back to Finding.refresh_from_db(), which raised
    Finding.DoesNotExist and failed the whole reimport with a 500.
    """

    def setUp(self):
        super().setUp()
        self.scan_type = "Acunetix Scan"
        self.user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="closeold_vanished")
        self.environment, _ = Development_Environment.objects.get_or_create(name="Development")
        product, _ = Product.objects.get_or_create(
            name="TestReimportCloseOldVanished",
            description="Test",
            prod_type=product_type,
        )
        self.engagement, _ = Engagement.objects.get_or_create(
            name="Close Old Vanished Findings",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        with (get_unit_tests_scans_path("acunetix") / "many_findings.xml").open(encoding="utf-8") as scan:
            importer = DefaultImporter(
                close_old_findings=False,
                user=self.user,
                lead=self.user,
                scan_date=None,
                environment=self.environment,
                active=True,
                verified=False,
                engagement=self.engagement,
                scan_type=self.scan_type,
            )
            self.test, _, len_new_findings, _, _, _, _ = importer.process_scan(scan)
        self.assertEqual(4, len_new_findings)

    def _reimporter(self):
        return DefaultReImporter(
            test=self.test,
            user=self.user,
            lead=self.user,
            scan_date=None,
            environment=self.environment,
            active=True,
            verified=False,
            scan_type=self.scan_type,
            close_old_findings=True,
        )

    def test_close_old_findings_skips_finding_deleted_during_reimport(self):
        """A candidate deleted after it was collected is skipped; the rest still close."""
        findings = list(self.test.finding_set.all())
        self.assertEqual(4, len(findings))
        vanished, *remaining = findings
        vanished_pk = vanished.pk
        # Simulate the concurrent delete: the row is gone, the in-memory instance is not
        Finding.objects.filter(pk=vanished_pk).delete()

        closed_findings = self._reimporter().close_old_findings(findings)

        closed_pks = {finding.pk for finding in closed_findings}
        self.assertNotIn(vanished_pk, closed_pks, msg="deleted finding must not be closed")
        self.assertEqual(
            {finding.pk for finding in remaining}, closed_pks,
            msg="every candidate that still exists must be closed",
        )
        # Closing must not re-insert the deleted row
        self.assertFalse(Finding.objects.filter(pk=vanished_pk).exists())
        for finding in remaining:
            finding.refresh_from_db()
            self.assertTrue(finding.is_mitigated)

    def test_close_old_findings_skips_unsaved_finding(self):
        """A candidate without a primary key has no row to refresh and cannot be closed."""
        findings = list(self.test.finding_set.all())
        unsaved_finding = Finding(
            title="Unsaved close-old candidate",
            test=self.test,
            severity="Low",
            reporter=self.user,
        )

        closed_findings = self._reimporter().close_old_findings([unsaved_finding, *findings])

        self.assertEqual(
            {finding.pk for finding in findings},
            {finding.pk for finding in closed_findings},
        )
        self.assertIsNone(unsaved_finding.pk, msg="close_old_findings must not save a new finding")
