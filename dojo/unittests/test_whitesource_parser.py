from django.test import TestCase
from dojo.tools.whitesource.parser import WhitesourceJSONParser
from dojo.models import Test


class TestWhitesourceJSONParser(TestCase):

    def test_parse_without_file_has_no_findings(self):
        parser = WhitesourceJSONParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_no_vuln_has_no_findings(self):

        testfile = open("dojo/unittests/scans/whitesource_sample/okhttp_no_vuln.json")
        parser = WhitesourceJSONParser(testfile, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        testfile = open("dojo/unittests/scans/whitesource_sample/okhttp_one_vuln.json")
        parser = WhitesourceJSONParser(testfile, Test())
        self.assertEqual(1, len(parser.items))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        testfile = open("dojo/unittests/scans/whitesource_sample/okhttp_many_vuln.json")
        parser = WhitesourceJSONParser(testfile, Test())
        self.assertEqual(6, len(parser.items))
