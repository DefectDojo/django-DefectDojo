from django.test import TestCase
from dojo.tools.immuniweb.parser import ImmuniwebXMLParser
from dojo.models import Test


class TestImmuniwebParser(TestCase):

    def test_parse_without_file_has_no_findings(self):
        parser = ImmuniwebXMLParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/immuniweb/ImmuniWeb-0-vuln.xml")
        parser = ImmuniwebXMLParser(testfile, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        testfile = open("dojo/unittests/scans/immuniweb/ImmuniWeb-1-vuln.xml")
        parser = ImmuniwebXMLParser(testfile, Test())
        self.assertEqual(1, len(parser.items))

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        testfile = open("dojo/unittests/scans/immuniweb/ImmuniWeb-multiple-vuln.xml")
        parser = ImmuniwebXMLParser(testfile, Test())
        self.assertTrue(len(parser.items) > 2)
