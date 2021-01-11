from django.test import TestCase
from dojo.tools.scantist.parser import ScantistJSONParser
from dojo.models import Test


class TestScantistJSONParser(TestCase):

    def test_parse_without_file_has_no_findings(self):
        parser = ScantistJSONParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/scantist/scantist-no-vuln.json")
        parser = ScantistJSONParser(testfile, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        testfile = open("dojo/unittests/scans/scantist/scantist-one-vuln.json")
        parser = ScantistJSONParser(testfile, Test())
        self.assertEqual(1, len(parser.items))

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        testfile = open("dojo/unittests/scans/scantist/scantist-many-vuln.json")
        parser = ScantistJSONParser(testfile, Test())
        self.assertTrue(len(parser.items) > 2)
