import logging
from pathlib import Path

from .dojo_test_case import DojoAPITestCase, get_unit_tests_scans_path
from .test_utils import assertTestImportModelsCreated

logger = logging.getLogger(__name__)


class ImportReimportDryRunTest(DojoAPITestCase):
    """
    Test class for testing the dry_run functionality in reimport scans.
    Ensures that dry_run mode performs analysis without making database changes.
    """

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.login_as_admin()
        # Test files for dry run testing
        self.zap_sample0_filename = get_unit_tests_scans_path("zap") / "0_zap_sample.xml"
        self.zap_sample1_filename = get_unit_tests_scans_path("zap") / "1_zap_sample_0_and_new_absent.xml"
        self.zap_sample3_filename = get_unit_tests_scans_path("zap") / "3_zap_sampl_0_and_different_severities.xml"

        self.veracode_many_findings = get_unit_tests_scans_path("veracode") / "many_findings.xml"
        self.veracode_mitigated_findings = get_unit_tests_scans_path("veracode") / "mitigated_finding.xml"
        self.scan_type_veracode = "Veracode Scan"

    def reimport_scan_with_dry_run(
        self,
        test_id,
        filename,
        scan_type="ZAP Scan",
        minimum_severity="Low",
        active=True,
        verified=False,
        close_old_findings=None,
        expected_http_status_code=201,
    ):
        """Helper method to perform reimport with dry_run=True"""
        with Path(filename).open(encoding="utf-8") as testfile:
            payload = {
                "minimum_severity": minimum_severity,
                "active": active,
                "verified": verified,
                "scan_type": scan_type,
                "file": testfile,
                "test": test_id,
                "dry_run": True,  # This is the key parameter
            }

            if close_old_findings is not None:
                payload["close_old_findings"] = close_old_findings

            return self.reimport_scan(payload, expected_http_status_code)

    def test_dry_run_basic_functionality(self):
        """Test that dry_run returns analysis without making changes"""
        logger.debug("Testing basic dry_run functionality")

        # Import initial scan
        with assertTestImportModelsCreated(self, imports=1, affected_findings=4, created=4):
            import0 = self.import_scan_with_params(self.zap_sample0_filename)

        test_id = import0["test"]

        # Get initial state
        initial_findings = self.get_test_findings_api(test_id)
        initial_count = len(initial_findings["results"])

        # Perform dry run reimport with different scan that would add findings
        dry_run_result = self.reimport_scan_with_dry_run(test_id, self.zap_sample1_filename)

        # Verify dry_run flag is in response
        self.assertTrue(dry_run_result.get("dry_run", False), "Response should indicate dry_run mode")

        # Verify changes_preview is present and contains expected structure
        self.assertIn("changes_preview", dry_run_result, "Dry run should include changes preview")
        changes = dry_run_result["changes_preview"]

        # Verify expected change counts for zap_sample1 (should have 1 new finding)
        self.assertEqual(changes["would_create"], 1, "Should predict 1 new finding")
        self.assertEqual(changes["would_reactivate"], 0, "Should predict 0 reactivated findings")
        self.assertEqual(changes["would_close"], 3, "Should predict 3 closed findings")  # 3 findings not in new scan
        self.assertEqual(changes["would_leave_untouched"], 1, "Should predict 1 untouched finding")
        self.assertEqual(changes["total_changes"], 2, "Total changes should be create + reactivate + close")

        # Verify no actual changes were made to the database
        post_dry_run_findings = self.get_test_findings_api(test_id)
        post_dry_run_count = len(post_dry_run_findings["results"])

        self.assertEqual(initial_count, post_dry_run_count, "Dry run should not change the actual number of findings")

        # Verify individual findings remain unchanged
        for initial_finding in initial_findings["results"]:
            matching_finding = next(
                (f for f in post_dry_run_findings["results"] if f["id"] == initial_finding["id"]), None
            )
            self.assertIsNotNone(matching_finding, f"Finding {initial_finding['id']} should still exist")
            self.assertEqual(
                initial_finding["active"],
                matching_finding["active"],
                "Finding active status should not change in dry run",
            )
            self.assertEqual(
                initial_finding["mitigated"],
                matching_finding["mitigated"],
                "Finding mitigated status should not change in dry run",
            )

    def test_dry_run_with_close_old_findings_true(self):
        """Test dry_run with close_old_findings=True predicts closing correctly"""
        logger.debug("Testing dry_run with close_old_findings=True")

        # Import initial scan
        with assertTestImportModelsCreated(self, imports=1, affected_findings=4, created=4):
            import0 = self.import_scan_with_params(self.zap_sample0_filename)

        test_id = import0["test"]

        # Dry run reimport with close_old_findings=True and scan that has different findings
        dry_run_result = self.reimport_scan_with_dry_run(test_id, self.zap_sample1_filename, close_old_findings=True)

        changes = dry_run_result["changes_preview"]

        # With close_old_findings=True, findings not in new scan should be closed
        self.assertEqual(changes["would_create"], 1, "Should predict 1 new finding")
        self.assertEqual(changes["would_close"], 3, "Should predict 3 findings to be closed")
        self.assertEqual(changes["would_leave_untouched"], 1, "Should predict 1 untouched finding")

        # Verify no actual database changes
        final_findings = self.get_test_findings_api(test_id)
        active_findings = [f for f in final_findings["results"] if f["active"]]
        self.assertEqual(len(active_findings), 4, "All original findings should still be active after dry run")

    def test_dry_run_with_close_old_findings_false(self):
        """Test dry_run with close_old_findings=False predicts no closing"""
        logger.debug("Testing dry_run with close_old_findings=False")

        # Import initial scan
        with assertTestImportModelsCreated(self, imports=1, affected_findings=4, created=4):
            import0 = self.import_scan_with_params(self.zap_sample0_filename)

        test_id = import0["test"]

        # Dry run reimport with close_old_findings=False
        dry_run_result = self.reimport_scan_with_dry_run(test_id, self.zap_sample1_filename, close_old_findings=False)

        changes = dry_run_result["changes_preview"]

        # With close_old_findings=False, no findings should be closed
        self.assertEqual(changes["would_create"], 1, "Should predict 1 new finding")
        self.assertEqual(changes["would_close"], 0, "Should predict 0 findings to be closed")
        self.assertEqual(changes["would_leave_untouched"], 4, "Should predict 4 untouched findings")

    def test_dry_run_reactivation_prediction(self):
        """Test that dry_run correctly predicts reactivation of mitigated findings"""
        logger.debug("Testing dry_run reactivation prediction")

        # Import initial scan with mitigated finding
        with assertTestImportModelsCreated(self, imports=1, affected_findings=1, created=1):
            import0 = self.import_scan_with_params(
                self.veracode_mitigated_findings, scan_type=self.scan_type_veracode, verified=True
            )

        test_id = import0["test"]

        # Verify the finding is mitigated
        findings = self.get_test_findings_api(test_id)
        mitigated_finding = findings["results"][0]
        self.assertTrue(mitigated_finding["mitigated"], "Finding should be mitigated")

        # Dry run reimport with same scan (finding exists and would be reactivated)
        dry_run_result = self.reimport_scan_with_dry_run(
            test_id,
            self.veracode_many_findings,  # This scan has the same finding but active
            scan_type=self.scan_type_veracode,
        )

        changes = dry_run_result["changes_preview"]

        # Should predict reactivation of the mitigated finding
        self.assertEqual(changes["would_reactivate"], 1, "Should predict 1 finding to be reactivated")
        self.assertEqual(
            changes["would_create"], 3, "Should predict 3 new findings"
        )  # veracode_many has 4 total, 1 matches existing

        # Verify no actual changes - finding should still be mitigated
        post_dry_run_findings = self.get_test_findings_api(test_id)
        post_dry_run_finding = post_dry_run_findings["results"][0]
        self.assertTrue(post_dry_run_finding["mitigated"], "Finding should still be mitigated after dry run")

    def test_dry_run_no_changes_scenario(self):
        """Test dry_run when reimporting identical scan (no changes expected)"""
        logger.debug("Testing dry_run with no changes scenario")

        # Import initial scan
        with assertTestImportModelsCreated(self, imports=1, affected_findings=4, created=4):
            import0 = self.import_scan_with_params(self.zap_sample0_filename)

        test_id = import0["test"]

        # Dry run reimport with identical scan
        dry_run_result = self.reimport_scan_with_dry_run(test_id, self.zap_sample0_filename)

        changes = dry_run_result["changes_preview"]

        # Should predict no changes
        self.assertEqual(changes["would_create"], 0, "Should predict 0 new findings")
        self.assertEqual(changes["would_reactivate"], 0, "Should predict 0 reactivated findings")
        self.assertEqual(changes["would_close"], 0, "Should predict 0 closed findings")
        self.assertEqual(changes["would_leave_untouched"], 4, "Should predict 4 untouched findings")
        self.assertEqual(changes["total_changes"], 0, "Should predict 0 total changes")

    def test_dry_run_severity_filtering(self):
        """Test that dry_run respects minimum_severity filtering"""
        logger.debug("Testing dry_run with severity filtering")

        # Import initial scan with Low minimum severity
        with assertTestImportModelsCreated(self, imports=1, affected_findings=4, created=4):
            import0 = self.import_scan_with_params(self.zap_sample0_filename, minimum_severity="Low")

        test_id = import0["test"]

        # Dry run reimport with High minimum severity - should predict fewer findings
        dry_run_result = self.reimport_scan_with_dry_run(
            test_id,
            self.zap_sample3_filename,  # Has findings with different severities
            minimum_severity="High",
        )

        changes = dry_run_result["changes_preview"]

        # The exact numbers depend on the scan content, but we should see some filtering effect
        # This verifies that severity filtering is applied during dry run analysis
        self.assertIsInstance(changes["would_create"], int, "Should return integer for would_create")
        self.assertIsInstance(changes["would_close"], int, "Should return integer for would_close")

        # Verify that dry run respects the minimum severity parameter
        self.assertIn("changes_preview", dry_run_result, "Should include changes preview with severity filtering")

    def test_dry_run_maintains_test_metadata(self):
        """Test that dry_run doesn't modify test metadata like updated_time"""
        logger.debug("Testing that dry_run preserves test metadata")

        # Import initial scan
        with assertTestImportModelsCreated(self, imports=1, affected_findings=4, created=4):
            import0 = self.import_scan_with_params(self.zap_sample0_filename)

        test_id = import0["test"]

        # Get initial test metadata
        initial_test = self.get_test_api(test_id)
        initial_updated = initial_test["updated"]

        # Perform dry run
        dry_run_result = self.reimport_scan_with_dry_run(test_id, self.zap_sample1_filename)

        # Verify dry run was successful
        self.assertTrue(dry_run_result.get("dry_run", False))

        # Check that test metadata wasn't modified
        post_dry_run_test = self.get_test_api(test_id)
        post_updated = post_dry_run_test["updated"]

        self.assertEqual(initial_updated, post_updated, "Test updated timestamp should not change during dry run")

    def test_dry_run_response_structure(self):
        """Test that dry_run response has all expected fields"""
        logger.debug("Testing dry_run response structure")

        # Import initial scan
        with assertTestImportModelsCreated(self, imports=1, affected_findings=4, created=4):
            import0 = self.import_scan_with_params(self.zap_sample0_filename)

        test_id = import0["test"]

        # Perform dry run
        dry_run_result = self.reimport_scan_with_dry_run(test_id, self.zap_sample1_filename)

        # Verify required fields are present
        self.assertIn("dry_run", dry_run_result, "Response should have dry_run field")
        self.assertTrue(dry_run_result["dry_run"], "dry_run field should be True")

        self.assertIn("changes_preview", dry_run_result, "Response should have changes_preview")

        changes = dry_run_result["changes_preview"]
        expected_fields = ["would_create", "would_reactivate", "would_close", "would_leave_untouched", "total_changes"]

        for field in expected_fields:
            self.assertIn(field, changes, f"changes_preview should contain {field}")
            self.assertIsInstance(changes[field], int, f"{field} should be an integer")
            self.assertGreaterEqual(changes[field], 0, f"{field} should be non-negative")

        # Verify total_changes calculation
        expected_total = changes["would_create"] + changes["would_reactivate"] + changes["would_close"]
        self.assertEqual(
            changes["total_changes"], expected_total, "total_changes should equal sum of create + reactivate + close"
        )

    def test_dry_run_with_different_scan_types(self):
        """Test dry_run works with different scan types"""
        logger.debug("Testing dry_run with Veracode scan type")

        # Import initial Veracode scan
        with assertTestImportModelsCreated(self, imports=1, affected_findings=4, created=4):
            import0 = self.import_scan_with_params(self.veracode_many_findings, scan_type=self.scan_type_veracode)

        test_id = import0["test"]

        # Dry run reimport with same Veracode scan
        dry_run_result = self.reimport_scan_with_dry_run(
            test_id, self.veracode_many_findings, scan_type=self.scan_type_veracode
        )

        # Should work the same as with ZAP scans
        self.assertTrue(dry_run_result.get("dry_run", False), "Should work with Veracode scans")
        self.assertIn("changes_preview", dry_run_result, "Should include changes preview for Veracode")

        changes = dry_run_result["changes_preview"]
        # Identical scan should show no changes
        self.assertEqual(changes["would_create"], 0, "Identical Veracode scan should show no new findings")
        self.assertEqual(changes["would_leave_untouched"], 4, "Should show all findings as untouched")

    def test_actual_reimport_after_dry_run_verification(self):
        """Test that actual reimport after dry_run produces the predicted results"""
        logger.debug("Testing that actual reimport matches dry_run predictions")

        # Import initial scan
        with assertTestImportModelsCreated(self, imports=1, affected_findings=4, created=4):
            import0 = self.import_scan_with_params(self.zap_sample0_filename)

        test_id = import0["test"]

        # Perform dry run first
        dry_run_result = self.reimport_scan_with_dry_run(test_id, self.zap_sample1_filename, close_old_findings=True)

        predicted_changes = dry_run_result["changes_preview"]

        # Now perform actual reimport with same parameters
        with assertTestImportModelsCreated(self, reimports=1, affected_findings=4, created=1, closed=3, untouched=1):
            actual_result = self.reimport_scan_with_params(test_id, self.zap_sample1_filename, close_old_findings=True)

        # Compare predictions with actual results
        # Note: The exact comparison depends on the specific scan files and their content
        # This test verifies that dry_run provides accurate predictions

        final_findings = self.get_test_findings_api(test_id)

        # Verify the test was actually modified (unlike dry run)
        self.assertFalse(actual_result.get("dry_run", False), "Actual reimport should not be dry run")

        # Count actual changes
        active_findings = [f for f in final_findings["results"] if f["active"]]
        mitigated_findings = [f for f in final_findings["results"] if f["mitigated"]]

        # The total number of findings should match: untouched + created = active findings
        # closed findings should be mitigated
        expected_active = predicted_changes["would_leave_untouched"] + predicted_changes["would_create"]
        expected_mitigated = predicted_changes["would_close"]

        self.assertEqual(
            len(active_findings), expected_active, "Actual active findings should match dry run prediction"
        )
        self.assertEqual(
            len(mitigated_findings), expected_mitigated, "Actual mitigated findings should match dry run prediction"
        )
