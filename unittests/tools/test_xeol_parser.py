from dojo.models import Test
from dojo.tools.xeol.parser import XeolParser
from unittests.dojo_test_case import (
    DojoTestCase,
    get_unit_tests_scans_path,
)


class TestXeolParser(DojoTestCase):

    def test_parse_file_with_zero_finding(self):
        scan_path = get_unit_tests_scans_path("xeol") / "xeol_zero.json"
        testfile = scan_path.open(encoding="utf-8")
        parser = XeolParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_finding(self):
        scan_path = (
            get_unit_tests_scans_path("xeol") / "xeol_one_finding.json"
        )
        testfile = scan_path.open(encoding="utf-8")
        parser = XeolParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        finding = list(findings)[0]
        self.assertEqual(finding.title, "Perl EOL Information")
        self.assertEqual(finding.severity, "Critical")

    def test_parse_file_with_multiple_finding(self):
        scan_path = (
            get_unit_tests_scans_path("xeol") / "xeol_multiple_findings.json"
        )
        testfile = scan_path.open(encoding="utf-8")
        parser = XeolParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(8, len(findings))
        finding = list(findings)[0]
        self.assertEqual(finding.severity, "Critical")
        self.assertEqual(finding.cwe, 672)
        self.assertEqual(finding.component_name, "spring-boot")
        self.assertEqual(finding.component_version, "2.0.4.RELEASE")
        finding = list(findings)[2]
        title_expected = (
            "org.springframework.boot:spring-boot-autoconfigure "
            "EOL Information"
        )
        self.assertEqual(finding.title, title_expected)
        self.assertEqual(finding.severity, "Critical")
        self.assertEqual(finding.cwe, 672)
        self.assertEqual(
            finding.component_name, "spring-boot-autoconfigure"
        )
        self.assertEqual(finding.component_version, "2.0.4.RELEASE")
