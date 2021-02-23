from django.test import TestCase
from dojo.tools.wapiti.parser import WapitiParser
from dojo.models import Test


class TestWapitiParser(TestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/wapiti_sample/wapiti_no_vuln.xml")
        parser = WapitiParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_two_vuln_has_two_findings(self):
        testfile = open("dojo/unittests/scans/wapiti_sample/wapiti_one_vuln.xml")
        parser = WapitiParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        testfile = open("dojo/unittests/scans/wapiti_sample/wapiti_many_vuln.xml")
        parser = WapitiParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(5, len(findings))
