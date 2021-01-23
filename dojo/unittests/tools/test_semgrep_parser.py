from django.test import TestCase
from dojo.tools.semgrep.parser import SemgrepJSONParser
from dojo.models import Test


class TestSemGrepJSONParser(TestCase):

    def test_no_findings(self):
        parser = SemgrepJSONParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_one_finding(self):
        testfile = open("dojo/unittests/scans/semgrep/one_finding.json")
        parser = SemgrepJSONParser(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(parser.items))

    def test_parse_many_finding(self):
        testfile = open("dojo/unittests/scans/semgrep/many_findings.json")
        parser = SemgrepJSONParser(testfile, Test())
        testfile.close()
        self.assertEqual(3, len(parser.items))

    def test_parse_repeated_finding(self):
        testfile = open("dojo/unittests/scans/semgrep/repeated_findings.json")
        parser = SemgrepJSONParser(testfile, Test())
        testfile.close()
        self.assertEqual(2, len(parser.items))
