from django.test import TestCase
from dojo.tools.wapiti.parser import WapitiXMLParser
from dojo.models import Test


class TestWapitiParser(TestCase):

    def test_parse_without_file_has_no_findings(self):
        parser = WapitiXMLParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_no_vuln_has_no_findings(self):

        testfile = open("dojo/unittests/scans/wapiti_sample/wapiti_no_vuln.xml")
        parser = WapitiXMLParser(testfile, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_two_vuln_has_two_findings(self):
        testfile = open("dojo/unittests/scans/wapiti_sample/wapiti_one_vuln.xml")
        parser = WapitiXMLParser(testfile, Test())
        self.assertEqual(1, len(parser.items))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        testfile = open("dojo/unittests/scans/wapiti_sample/wapiti_many_vuln.xml")
        parser = WapitiXMLParser(testfile, Test())
        self.assertEqual(5, len(parser.items))
