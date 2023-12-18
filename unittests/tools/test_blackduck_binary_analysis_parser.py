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
            self.assertIsNotNone(finding.component)
            self.assertIsNotNone(finding.version)
            self.assertIsNotNone(finding.object_name)
            self.assertIsNotNone(finding.object_sha1)
            self.assertIsNotNone(finding.report_path)
            self.assertIsNotNone(finding.object_full_path)
            self.assertIsNotNone(finding.vuln_id_from_tool)
            self.assertIsNotNone(finding.unique_id_from_tool)

    def test_parse_many_vulns(self):
        testfile = Path(get_unit_tests_path() + "/scans/blackduck_binary_analysis/many_vulns.csv")
        parser = BlackduckBinaryAnalysisParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(5, len(findings))
        for finding in findings:
            self.assertIsNotNone(finding.title)
            self.assertIsNotNone(finding.description)
            self.assertIsNotNone(finding.severity)
            self.assertIsNotNone(finding.component)
            self.assertIsNotNone(finding.version)
            self.assertIsNotNone(finding.object_name)
            self.assertIsNotNone(finding.object_sha1)
            self.assertIsNotNone(finding.report_path)
            self.assertIsNotNone(finding.object_full_path)
            self.assertIsNotNone(finding.vuln_id_from_tool)
            self.assertIsNotNone(finding.unique_id_from_tool)
