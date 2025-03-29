from dojo.models import Test
from dojo.tools.sysdig.sysdig_cli.parser import SysdigCLIParser
from dojo.tools.sysdig.sysdig_reports.parser import SysdigReportsParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSysdigParsers(DojoTestCase):

    def test_sysdig_parser_with_no_vuln_has_no_findings(self):
        with open(get_unit_tests_scans_path("sysdig_reports") / "vulnerability_management_engine" / "sysdig_reports_zero_vul.csv", encoding="utf-8") as testfile:
            parser = SysdigReportsParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_sysdig_parser_with_one_criticle_vuln_has_one_findings(self):
        with open(get_unit_tests_scans_path("sysdig_reports") / "vulnerability_management_engine" / "sysdig_reports_one_vul.csv", encoding="utf-8") as testfile:
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

    def test_sysdig_parser_with_many_vuln_has_many_findings(self):
        with open(get_unit_tests_scans_path("sysdig_reports") / "vulnerability_management_engine" / "sysdig_reports_many_vul.csv", encoding="utf-8") as testfile:
            parser = SysdigReportsParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(50, len(findings))

    def test_sysdig_parser_missing_cve_field_id_from_csv_file(self):
        with self.assertRaises(ValueError) as context, \
          open(get_unit_tests_scans_path("sysdig_reports") / "vulnerability_management_engine" / "sysdig_reports_missing_cve_field.csv", encoding="utf-8") as testfile:
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
          open(get_unit_tests_scans_path("sysdig_reports") / "vulnerability_management_engine" / "sysdig_reports_not_starting_with_cve.csv", encoding="utf-8") as testfile:
            parser = SysdigReportsParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
        self.assertEqual(
            "Number of fields in row (22) does not match number of headers (21)", str(context.exception),
        )

    def test_sysdig_parser_json_with_many_findings(self):
        with open(get_unit_tests_scans_path("sysdig_reports") / "vulnerability_management_engine" / "sysdig.json", encoding="utf-8") as testfile:
            parser = SysdigReportsParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(207, len(findings))

    def test_sysdig_parser_with_many_vuln_has_many_findings_cli(self):
        with open(get_unit_tests_scans_path("sysdig_reports") / "cli" / "sysdig_reports_many_vul.csv", encoding="utf-8") as testfile:
            parser = SysdigCLIParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(31, len(findings))
            finding = findings[0]
            self.assertEqual("CVE-2013-7459 - pycrypto", finding.title)
            self.assertEqual("pycrypto", finding.component_name)
            self.assertEqual("2.6.1", finding.component_version)
            self.assertEqual("Critical", finding.severity)
            self.assertEqual("CVE-2013-7459", finding.unsaved_vulnerability_ids[0])
            self.assertEqual(9.8, finding.cvssv3_score)
            self.assertEqual("https://nvd.nist.gov/vuln/detail/CVE-2013-7459", finding.references)
            self.assertEqual("0.00587", finding.epss_score)

    def test_sysdig_parser_json_with_many_findings_cli(self):
        with open(get_unit_tests_scans_path("sysdig_reports") / "cli" / "sysdig_reports_many_vul.json", encoding="utf-8") as testfile:
            parser = SysdigCLIParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(31, len(findings))
            finding = findings[0]
            self.assertEqual("CVE-2023-50782 - cryptography - v42.0.0", finding.title)
            self.assertEqual("cryptography", finding.component_name)
            self.assertEqual("1.7.1", finding.component_version)
            self.assertEqual("High", finding.severity)
            self.assertEqual("CVE-2023-50782", finding.unsaved_vulnerability_ids[0])
            self.assertEqual(7.5, finding.cvssv3_score)
