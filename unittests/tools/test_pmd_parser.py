from ..dojo_test_case import DojoTestCase
from dojo.tools.pmd.parser import PmdParser
from dojo.models import Test


class TestPMDParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/pmd/pmd_no_vuln.csv")
        parser = PmdParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        testfile = open("unittests/scans/pmd/pmd_one_vuln.csv")
        parser = PmdParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        testfile = open("unittests/scans/pmd/pmd_many_vulns.csv")
        parser = PmdParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(16, len(findings))
        self.assertEqual("PMD rule UseUtilityClass", findings[0].title)
        self.assertEqual("Medium", findings[0].severity)
