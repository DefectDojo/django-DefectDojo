from ..dojo_test_case import DojoTestCase
from dojo.tools.chefinspect.parser import ChefInspectParser
from dojo.models import Test


class TestChefInspectParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/chefinspect/no_finding.log")
        parser = ChefInspectParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        testfile = open("unittests/scans/chefinspect/one_finding.log")
        parser = ChefInspectParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        testfile = open("unittests/scans/chefinspect/many_findings.log")
        parser = ChefInspectParser()
        findings = parser.get_findings(testfile, Test())
        self.assertTrue(10, len(findings))
