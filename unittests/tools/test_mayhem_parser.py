from dojo.models import Finding, Test
from dojo.tools.mayhem.parser import MayhemParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestMayhemParser(DojoTestCase):
    def common_checks(self, finding):
        self.assertLessEqual(len(finding.title), 250)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        if finding.cwe:
            self.assertIsInstance(finding.cwe, int)
        self.assertEqual(False, finding.static_finding)  # Mayhem is DAST!
        self.assertEqual(True, finding.dynamic_finding)  # Mayhem is DAST!

    def test_mcode_many_report(self):
        with (
            get_unit_tests_scans_path("mayhem") / "mayhem_code_many_vulns.sarif"
        ).open(encoding="utf-8") as testfile:
            parser = MayhemParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(8, len(findings))
            for finding in findings:
                self.common_checks(finding)
    
    def test_mapi_many_report(self):
        with (
            get_unit_tests_scans_path("mayhem") / "mayhem_api_many_vulns.sarif"
        ).open(encoding="utf-8") as testfile:
            parser = MayhemParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(20, len(findings))
            for finding in findings:
                self.common_checks(finding)

    def test_mcode_one_report(self):
        with (
            get_unit_tests_scans_path("mayhem") / "mayhem_code_one_vuln.sarif"
        ).open(encoding="utf-8") as testfile:
            parser = MayhemParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.common_checks(finding)
            self.assertEqual(20, finding.cwe)

    def test_mapi_one_report(self):
        with (
            get_unit_tests_scans_path("mayhem") / "mayhem_api_one_vuln.sarif"
        ).open(encoding="utf-8") as testfile:
            parser = MayhemParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.common_checks(finding)
            self.assertEqual(1392, finding.cwe)

    def test_mcode_no_vulns_report(self):
        with (
            get_unit_tests_scans_path("mayhem") / "mayhem_code_no_vulns.sarif"
        ).open(encoding="utf-8") as testfile:
            parser = MayhemParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_mapi_no_vulns_report(self):
        with (
            get_unit_tests_scans_path("mayhem") / "mayhem_api_no_vulns.sarif"
        ).open(encoding="utf-8") as testfile:
            parser = MayhemParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))