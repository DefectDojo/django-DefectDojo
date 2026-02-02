
from dojo.models import Test
from dojo.tools.sysdig_reports.parser import SysdigReportsParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSysdigParsers(DojoTestCase):

    def test_sysdig_parser_with_no_vuln_has_no_findings(self):
        with (get_unit_tests_scans_path("sysdig_reports") / "sysdig_reports_zero_vul.csv").open(encoding="utf-8") as testfile:
            parser = SysdigReportsParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_sysdig_parser_with_one_criticle_vuln_has_one_findings(self):
        with (get_unit_tests_scans_path("sysdig_reports") / "sysdig_reports_one_vul.csv").open(encoding="utf-8") as testfile:
            parser = SysdigReportsParser()
            findings = parser.get_findings(testfile, Test())
            self.validate_locations(findings)
            self.assertEqual(1, len(findings))
            self.assertEqual("com.fasterxml.jackson.core:jackson-databind", findings[0].component_name)
            self.assertEqual("2.9.7", findings[0].component_version)
            self.assertEqual("CVE-2018-19360", findings[0].unsaved_vulnerability_ids[0])
            self.assertEqual(None, findings[0].epss_score)

            # Verify tags are created correctly without spaces
            finding = findings[0]
            tags_list = finding.unsaved_tags
            self.assertIn("PackageName:com.fasterxml.jackson.core:jackson-databind", tags_list)
            self.assertIn("PackageVersion:2.9.7", tags_list)
            self.assertIn("VulnId:CVE-2018-19360", tags_list)
            # Should not have K8s-related tags since this CSV doesn't include those fields
            k8s_tags = [tag for tag in tags_list if tag.startswith(("Cluster:", "Namespace:", "WorkloadName:"))]
            self.assertEqual(0, len(k8s_tags))

    def test_sysdig_parser_with_many_vuln_has_many_findings(self):
        with (get_unit_tests_scans_path("sysdig_reports") / "sysdig_reports_many_vul.csv").open(encoding="utf-8") as testfile:
            parser = SysdigReportsParser()
            findings = parser.get_findings(testfile, Test())
            self.validate_locations(findings)
            self.assertEqual(50, len(findings))

    def test_sysdig_parser_missing_cve_field_id_from_csv_file(self):
        with self.assertRaises(ValueError) as context, \
          (get_unit_tests_scans_path("sysdig_reports") / "sysdig_reports_missing_cve_field.csv").open(encoding="utf-8") as testfile:
            parser = SysdigReportsParser()
            findings = parser.get_findings(testfile, Test())
            self.validate_locations(findings)
        self.assertEqual(
            "Number of fields in row (22) does not match number of headers (21)", str(context.exception),
        )

    def test_sysdig_parser_missing_cve_field_not_starting_with_cve(self):
        with self.assertRaises(ValueError) as context, \
          (get_unit_tests_scans_path("sysdig_reports") / "sysdig_reports_not_starting_with_cve.csv").open(encoding="utf-8") as testfile:
            parser = SysdigReportsParser()
            findings = parser.get_findings(testfile, Test())
            self.validate_locations(findings)
        self.assertEqual(
            "Number of fields in row (22) does not match number of headers (21)", str(context.exception),
        )

    def test_sysdig_parser_json_with_many_findings(self):
        with (get_unit_tests_scans_path("sysdig_reports") / "sysdig.json").open(encoding="utf-8") as testfile:
            parser = SysdigReportsParser()
            findings = parser.get_findings(testfile, Test())
            self.validate_locations(findings)
            self.assertEqual(207, len(findings))

    # New test cases for 2025 format
    def test_sysdig_parser_2025_csv_format(self):
        """Test CSV parsing with new 2025 format headers (Vulnerability Name, Vulnerability Severity)"""
        with (get_unit_tests_scans_path("sysdig_reports") / "sysdig-2025.csv").open(encoding="utf-8") as testfile:
            parser = SysdigReportsParser()
            findings = parser.get_findings(testfile, Test())
            self.validate_locations(findings)
            # Verify each CVE appears exactly once
            all_vuln_ids = [vid for f in findings for vid in f.unsaved_vulnerability_ids]
            self.assertEqual(1, all_vuln_ids.count("CVE-2025-6021"), "CVE-2025-6021 should appear exactly once")
            self.assertEqual(1, all_vuln_ids.count("CVE-2011-10007"), "CVE-2011-10007 should appear exactly once")
            for finding in findings:
                if "CVE-2025-6021" in finding.unsaved_vulnerability_ids:
                    self.assertEqual(finding.severity, "Info")  # Other maps to Info
                if "CVE-2011-10007" in finding.unsaved_vulnerability_ids:
                    self.assertEqual(finding.severity, "Info")  # Negligible maps to Info

            self.assertEqual(6, len(findings))

            # Test specific finding details from the 2025 format
            finding = findings[0]
            self.assertEqual("CVE-2005-2541", finding.unsaved_vulnerability_ids[0])
            self.assertEqual("package name 1", finding.component_name)
            self.assertEqual("0.0.0.1", finding.component_version)
            self.assertEqual("Info", finding.severity)  # Negligible maps to Info

            # Test a Critical severity finding
            critical_findings = [f for f in findings if f.severity == "Critical"]
            self.assertGreater(len(critical_findings), 0)
            critical_finding = critical_findings[0]
            self.assertIn("CVE-", critical_finding.unsaved_vulnerability_ids[0])

    def test_sysdig_parser_2025_json_format(self):
        """Test JSON parsing with new 2025 format that has metadata before data section"""
        with (get_unit_tests_scans_path("sysdig_reports") / "sysdig-2025.json").open(encoding="utf-8") as testfile:
            parser = SysdigReportsParser()
            findings = parser.get_findings(testfile, Test())
            self.validate_locations(findings)
            # Verify each CVE appears exactly once
            all_vuln_ids = [vid for f in findings for vid in f.unsaved_vulnerability_ids]
            self.assertEqual(1, all_vuln_ids.count("CVE-2023-45322"), "CVE-2023-45322 should appear exactly once")
            self.assertEqual(1, all_vuln_ids.count("CVE-2025-48379"), "CVE-2025-48379 should appear exactly once")
            for finding in findings:
                if "CVE-2023-45322" in finding.unsaved_vulnerability_ids:
                    self.assertEqual(finding.severity, "Info")  # Negligible maps to Info
                if "CVE-2025-48379" in finding.unsaved_vulnerability_ids:
                    self.assertEqual(finding.severity, "Info")  # Other maps to Info

            # Should parse successfully even with metadata before data section
            self.assertGreater(len(findings), 0)

            # Test that vulnerability IDs are properly extracted
            vuln_ids = [f.unsaved_vulnerability_ids[0] for f in findings if f.unsaved_vulnerability_ids]
            self.assertGreater(len(vuln_ids), 0)
            # Check that we have CVE IDs in the findings
            cve_findings = [vid for vid in vuln_ids if vid.startswith("CVE-")]
            self.assertGreater(len(cve_findings), 0)
