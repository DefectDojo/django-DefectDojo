from ..dojo_test_case import DojoTestCase, get_unit_tests_path
from dojo.tools.blackduck_binary_analysis.parser import BlackduckBinaryAnalysisParser
from dojo.models import Test
from pathlib import Path


class TestBlackduckBinaryAnalysisParser(DojoTestCase):
    def test_parse_no_vulns(self):
        testfile = Path(get_unit_tests_path() + "/scans/blackduck_binary_analysis/no_vuln.csv")
        parser = BlackduckBinaryAnalysisParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_one_vuln(self):
        testfile = Path(get_unit_tests_path() + "/scans/blackduck_binary_analysis/one_vuln.csv")
        parser = BlackduckBinaryAnalysisParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        for finding in findings:
            self.assertIsNotNone(finding.title)
            self.assertIsNotNone(finding.description)
            self.assertIsNotNone(finding.severity)
            self.assertIsNotNone(finding.component_name)
            self.assertIsNotNone(finding.component_version)
            self.assertIsNotNone(finding.file_path)
            self.assertIsNotNone(finding.vuln_id_from_tool)
            self.assertIsNotNone(finding.unique_id_from_tool)

        self.assertEqual("instrument.dll: zlib 1.2.13 Vulnerable to CVE-2023-45853", findings[0].title)
        self.assertEqual("Critical", findings[0].severity)
        self.assertEqual("zlib", findings[0].component_name)
        self.assertEqual("1.2.13", findings[0].component_version)
        self.assertEqual("JRE.msi:JRE.msi-30276-90876123.cab:instrument.dll", findings[0].file_path)
        self.assertEqual("CVE-2023-45853", findings[0].vuln_id_from_tool)

    def test_parse_many_vulns(self):
        testfile = Path(get_unit_tests_path() + "/scans/blackduck_binary_analysis/many_vulns.csv")
        parser = BlackduckBinaryAnalysisParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(5, len(findings))
        for finding in findings:
            self.assertIsNotNone(finding.title)
            self.assertIsNotNone(finding.description)
            self.assertIsNotNone(finding.severity)
            self.assertIsNotNone(finding.component_name)
            self.assertIsNotNone(finding.component_version)
            self.assertIsNotNone(finding.file_path)
            self.assertIsNotNone(finding.vuln_id_from_tool)
            self.assertIsNotNone(finding.unique_id_from_tool)
