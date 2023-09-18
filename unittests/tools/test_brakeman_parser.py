from ..dojo_test_case import DojoParserTestCase
from dojo.tools.brakeman.parser import BrakemanParser
from dojo.models import Test


class TestBrakemanParser(DojoParserTestCase):

    parser = BrakemanParser()

    def test_parse_file_no_finding(self):
        testfile = open("unittests/scans/brakeman/no_finding.json")
        findings = self.parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_has_two_findings(self):
        testfile = open("unittests/scans/brakeman/two_findings.json")
        findings = self.parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(2, len(findings))

    def test_parse_file_has_many_findings(self):
        testfile = open("unittests/scans/brakeman/many_findings.json")
        findings = self.parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(18, len(findings))
