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
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
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
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(50, len(findings))

    def test_sysdig_parser_missing_cve_field_id_from_csv_file(self):
        with self.assertRaises(ValueError) as context, \
          (get_unit_tests_scans_path("sysdig_reports") / "sysdig_reports_missing_cve_field.csv").open(encoding="utf-8") as testfile:
            parser = SysdigReportsParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
        self.assertEqual(
            "Number of fields in row (22) does not match number of headers (21)", str(context.exception),
        )

    def test_sysdig_parser_missing_cve_field_not_starting_with_cve(self):
        with self.assertRaises(ValueError) as context, \
          (get_unit_tests_scans_path("sysdig_reports") / "sysdig_reports_not_starting_with_cve.csv").open(encoding="utf-8") as testfile:
            parser = SysdigReportsParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
        self.assertEqual(
            "Number of fields in row (22) does not match number of headers (21)", str(context.exception),
        )

    def test_sysdig_parser_json_with_many_findings(self):
        with (get_unit_tests_scans_path("sysdig_reports") / "sysdig.json").open(encoding="utf-8") as testfile:
            parser = SysdigReportsParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(207, len(findings))
