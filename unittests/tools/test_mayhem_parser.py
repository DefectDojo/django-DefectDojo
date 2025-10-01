from dojo.models import Finding, Test
from dojo.tools.mayhem.parser import MayhemParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestMayhemParser(DojoTestCase):
    def common_checks(self, finding):
        self.assertLessEqual(len(finding.title), 250)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        if finding.cwe:
            self.assertIsInstance(finding.cwe, int)
        self.assertFalse(finding.static_finding)  # Mayhem is DAST!
        self.assertTrue(finding.dynamic_finding)  # Mayhem is DAST!
        self.assertIsInstance(finding.description, str)
        self.assertEqual(1, finding.reporter_id)

    def test_mcode_many_report(self):
        with (
            get_unit_tests_scans_path("mayhem") / "mayhem_code_many_vulns.sarif"
        ).open(encoding="utf-8") as testfile:
            parser = MayhemParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(8, len(findings))
            for finding in findings:
                self.common_checks(finding)
            # Sample a finding
            finding = findings[3]
            self.assertEqual("Uncontrolled Resource Consumption", finding.title)
            self.assertEqual(400, finding.cwe)
            self.assertEqual("High", finding.severity)
            self.assertEqual("https://www.mayhem.security/", finding.references)
            self.assertEqual(48, finding.line)
            self.assertEqual("app/src/gps_uploader.c", finding.file_path)
            self.assertEqual("MI102", finding.vuln_id_from_tool)

    def test_mapi_many_report(self):
        with (
            get_unit_tests_scans_path("mayhem") / "mayhem_api_many_vulns.sarif"
        ).open(encoding="utf-8") as testfile:
            parser = MayhemParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(20, len(findings))
            for finding in findings:
                self.common_checks(finding)
            # Sample a finding
            finding = findings[7]
            self.assertEqual("Internal Server Error in POST /pet.", finding.title)
            self.assertEqual(550, finding.cwe)
            self.assertEqual("High", finding.severity)
            self.assertEqual(497, finding.line)
            self.assertEqual("io/swagger/oas/inflector/controllers/OpenAPIOperationController.java", finding.file_path)
            self.assertEqual("internal-server-error (io.swagger.oas.inflector.utils.ApiException)", finding.vuln_id_from_tool)

    def test_mcode_one_report(self):
        with (
            get_unit_tests_scans_path("mayhem") / "mayhem_code_one_vuln.sarif"
        ).open(encoding="utf-8") as testfile:
            parser = MayhemParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.common_checks(finding)
            self.assertEqual("Improper Input Validation", finding.title)
            self.assertEqual(20, finding.cwe)
            self.assertEqual("High", finding.severity)
            self.assertEqual("https://www.mayhem.security/", finding.references)
            self.assertEqual("MI101", finding.vuln_id_from_tool)

    def test_mapi_one_report(self):
        with (
            get_unit_tests_scans_path("mayhem") / "mayhem_api_one_vuln.sarif"
        ).open(encoding="utf-8") as testfile:
            parser = MayhemParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.common_checks(finding)
            self.assertEqual("Default Credentials Used in GET /info.", finding.title)
            self.assertEqual(1392, finding.cwe)
            self.assertEqual("High", finding.severity)
            self.assertEqual("default-credentials", finding.vuln_id_from_tool)

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
