
from dojo.models import Test
from dojo.tools.sysdig_cli.parser import SysdigCLIParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSysdigParsers(DojoTestCase):

    def test_sysdig_parser_with_many_vuln_has_many_findings_cli(self):
        with (get_unit_tests_scans_path("sysdig_cli") / "sysdig_reports_many_vul.csv").open(encoding="utf-8") as testfile:
            parser = SysdigCLIParser()
            findings = parser.get_findings(testfile, Test())
            self.validate_locations(findings)
            # Verify each CVE appears exactly once
            all_vuln_ids = [vid for f in findings for vid in f.unsaved_vulnerability_ids]
            self.assertEqual(1, all_vuln_ids.count("CVE-2023-5752"), "CVE-2023-5752 should appear exactly once")
            self.assertEqual(1, all_vuln_ids.count("CVE-2024-49766"), "CVE-2024-49766 should appear exactly once")
            for finding in findings:
                if "CVE-2023-5752" in finding.unsaved_vulnerability_ids:
                    self.assertEqual(finding.severity, "Info")  # Negligible maps to Info
                if "CVE-2024-49766" in finding.unsaved_vulnerability_ids:
                    self.assertEqual(finding.severity, "Info")  # Other maps to Info

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
        with (get_unit_tests_scans_path("sysdig_cli") / "sysdig_reports_many_vul.json").open(encoding="utf-8") as testfile:
            parser = SysdigCLIParser()
            findings = parser.get_findings(testfile, Test())
            self.validate_locations(findings)
            # Verify each CVE appears exactly once
            all_vuln_ids = [vid for f in findings for vid in f.unsaved_vulnerability_ids]
            self.assertEqual(1, all_vuln_ids.count("CVE-2024-49766"), "CVE-2024-49766 should appear exactly once")
            self.assertEqual(1, all_vuln_ids.count("CVE-2024-49767"), "CVE-2024-49767 should appear exactly once")
            for finding in findings:
                if "CVE-2024-49766" in finding.unsaved_vulnerability_ids:
                    self.assertEqual(finding.severity, "Info")  # Negligible maps to Info
                if "CVE-2024-49767" in finding.unsaved_vulnerability_ids:
                    self.assertEqual(finding.severity, "Info")  # Other maps to Info

            self.assertEqual(31, len(findings))
            finding = findings[0]
            self.assertEqual("CVE-2023-50782 - cryptography - v42.0.0", finding.title)
            self.assertEqual("cryptography", finding.component_name)
            self.assertEqual("1.7.1", finding.component_version)
            self.assertEqual("High", finding.severity)
            self.assertEqual("CVE-2023-50782", finding.unsaved_vulnerability_ids[0])
            self.assertEqual(7.5, finding.cvssv3_score)
