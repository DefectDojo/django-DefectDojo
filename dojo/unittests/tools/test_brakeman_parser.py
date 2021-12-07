from django.test import TestCase
from dojo.tools.brakeman.parser import BrakemanParser
from dojo.models import Test


class TestBrakemanParser(TestCase):

    def test_parse_file_no_finding(self):
        testfile = open("dojo/unittests/scans/brakeman/no_finding.json")
        parser = BrakemanParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_has_two_findings(self):
        testfile = open("dojo/unittests/scans/brakeman/two_findings.json")
        parser = BrakemanParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(2, len(findings))

    def test_parse_file_has_many_findings(self):
        testfile = open("dojo/unittests/scans/brakeman/many_findings.json")
        parser = BrakemanParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(18, len(findings))
