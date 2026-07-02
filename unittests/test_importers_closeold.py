import logging
from unittest.mock import patch

from django.utils import timezone

import dojo.risk_acceptance.helper as ra_helper
from dojo.importers.default_importer import DefaultImporter
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import Development_Environment, Engagement, Product, Product_Type, User

from .dojo_test_case import DojoTestCase, get_unit_tests_scans_path

logger = logging.getLogger(__name__)


class TestDojoCloseOld(DojoTestCase):
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

    def test_defer_product_grading_skips_close_old_grade(self):
        """
        With defer_product_grading=True, an import that closes old findings must skip the
        close-old grade in close_old_findings (as well as the end-of-process grade), so the
        importer never calls perform_product_grading -- the caller grades once itself. Pins the
        close_old_findings deferral guard; the per-batch/end guards are covered in
        test_importers_importer.py.
        """
        scan_type = "Acunetix Scan"
        user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="closeold-defer")
        environment, _ = Development_Environment.objects.get_or_create(name="Development")
        product, _ = Product.objects.get_or_create(
            name="TestDojoCloseOldDefer",
            description="Test",
            prod_type=product_type,
        )
        engagement, _ = Engagement.objects.get_or_create(
            name="Close Old Defer Grading",
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
        # Seed the engagement with several findings (no close-old on this first import).
        with (get_unit_tests_scans_path("acunetix") / "many_findings.xml").open(encoding="utf-8") as many_findings_scan:
            DefaultImporter(close_old_findings=False, **import_options).process_scan(many_findings_scan)
        # Import a single finding with close-old + deferral: the other findings close, but the
        # importer must not grade (neither the end pass nor the close-old pass). perform_product_grading
        # is only referenced by those two direct call sites in default_importer, so a call here would
        # mean a guard regressed.
        with (get_unit_tests_scans_path("acunetix") / "one_finding.xml").open(encoding="utf-8") as single_finding_scan:
            importer = DefaultImporter(close_old_findings=True, defer_product_grading=True, **import_options)
            with patch("dojo.importers.default_importer.perform_product_grading") as grade:
                _, _, _, len_closed_findings, _, _, _ = importer.process_scan(single_finding_scan)
            self.assertGreater(len_closed_findings, 0, "old findings must actually close, or the close-old guard isn't exercised")
            grade.assert_not_called()

    def test_reimport_defer_product_grading_skips_close_old_and_end_grade(self):
        """
        Reimport counterpart to test_defer_product_grading_skips_close_old_grade: with
        defer_product_grading=True, a reimport that mitigates old findings must skip both the
        end-of-process grade and the close-old grade in DefaultReImporter, so the reimporter never
        calls perform_product_grading -- the caller grades once. Pins the reimporter's end and
        close-old deferral guards (its per-batch guard is covered by the Pro connectors tests).
        """
        scan_type = "Acunetix Scan"
        user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="closeold-defer-reimport")
        environment, _ = Development_Environment.objects.get_or_create(name="Development")
        product, _ = Product.objects.get_or_create(
            name="TestDojoCloseOldDeferReimport",
            description="Test",
            prod_type=product_type,
        )
        engagement, _ = Engagement.objects.get_or_create(
            name="Close Old Defer Grading Reimport",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        common = {
            "user": user,
            "lead": user,
            "scan_date": None,
            "environment": environment,
            "active": True,
            "verified": False,
            "scan_type": scan_type,
        }
        # Seed a test with several findings via an initial import.
        with (get_unit_tests_scans_path("acunetix") / "many_findings.xml").open(encoding="utf-8") as many_findings_scan:
            importer = DefaultImporter(engagement=engagement, close_old_findings=False, **common)
            test, _, _, _, _, _, _ = importer.process_scan(many_findings_scan)
        # Reimport a single finding with close-old + deferral: the absent findings mitigate, but the
        # reimporter must not grade. perform_product_grading is only referenced by the end and
        # close-old call sites in default_reimporter, so a call here means a guard regressed.
        with (get_unit_tests_scans_path("acunetix") / "one_finding.xml").open(encoding="utf-8") as single_finding_scan:
            reimporter = DefaultReImporter(test=test, close_old_findings=True, defer_product_grading=True, **common)
            with patch("dojo.importers.default_reimporter.perform_product_grading") as grade:
                reimporter.process_scan(single_finding_scan)
            self.assertGreater(
                test.finding_set.filter(is_mitigated=True).count(),
                0,
                "old findings must actually mitigate, or the close-old guard isn't exercised",
            )
            grade.assert_not_called()

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
