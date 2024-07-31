from dojo.models import Test
from dojo.tools.pmd.parser import PmdParser
from unittests.dojo_test_case import DojoTestCase


class TestPMDParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        with open("unittests/scans/pmd/pmd_no_vuln.csv") as testfile:
            parser = PmdParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        with open("unittests/scans/pmd/pmd_one_vuln.csv") as testfile:
            parser = PmdParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        with open("unittests/scans/pmd/pmd_many_vulns.csv") as testfile:
            parser = PmdParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(16, len(findings))
            self.assertEqual("PMD rule UseUtilityClass", findings[0].title)
            self.assertEqual("Medium", findings[0].severity)
