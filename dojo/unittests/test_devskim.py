from django.test import TestCase
from dojo.tools.brakeman.parser import BrakemanScanParser
from dojo.models import Test


class TestDevSkimScanParser(TestCase):

    def test_parse_without_file_has_no_finding(self):
        parser = DevSkimParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_no_finding(self):
        testfile = open("dojo/unittests/scans/brakeman/no_finding.json")
        parser = DevSkimParser(testfile, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_has_two_findings(self):
        testfile = open("dojo/unittests/scans/brakeman/two_findings.json")
        parser = DevSkimParser(testfile, Test())
        testfile.close()
        self.assertEqual(4, len(parser.items))
