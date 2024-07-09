from dojo.models import Test
from dojo.tools.brakeman.parser import BrakemanParser
from unittests.dojo_test_case import DojoTestCase


class TestBrakemanParser(DojoTestCase):

    def test_parse_file_no_finding(self):
        with open("unittests/scans/brakeman/no_finding.json") as testfile:
            parser = BrakemanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_has_two_findings(self):
        with open("unittests/scans/brakeman/two_findings.json") as testfile:
            parser = BrakemanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))

    def test_parse_file_has_many_findings(self):
        with open("unittests/scans/brakeman/many_findings.json") as testfile:
            parser = BrakemanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(18, len(findings))
