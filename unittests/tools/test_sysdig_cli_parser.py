from dojo.models import Test
from dojo.tools.sysdig.sysdig_cli.parser import SysdigCLIParser
from dojo.tools.sysdig.sysdig_reports.parser import SysdigReportsParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSysdigParsers(DojoTestCase):

    def test_sysdig_parser_with_many_vuln_has_many_findings_cli(self):
        with open(get_unit_tests_scans_path("sysdig_cli") / "sysdig_reports_many_vul.csv", encoding="utf-8") as testfile:
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
        with open(get_unit_tests_scans_path("sysdig_cli") / "sysdig_reports_many_vul.json", encoding="utf-8") as testfile:
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
