from ..dojo_test_case import DojoTestCase
from dojo.tools.blackduck_binary_analysis.parser import BlackduckBinaryAnalysisParser
from dojo.models import Test


class TestBlackduckBinaryAnalysisParser(DojoTestCase):
    def test_parse_no_vulns(self):
        testfile = open("unittests/scans/blackduck_binary_analysis/no_vuln.csv")
        parser = BlackduckBinaryAnalysisParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_one_vuln(self):
        testfile = open("unittests/scans/blackduck_binary_analysis/one_vuln.csv")
        parser = BlackduckBinaryAnalysisParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_many_vulns(self):
        testfile = open("unittests/scans/blackduck_binary_analysis/many_vulns.csv")
        parser = BlackduckBinaryAnalysisParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(5, len(findings))
