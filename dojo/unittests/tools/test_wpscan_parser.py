from django.test import TestCase
from dojo.tools.wpscan.parser import WpscanParser
from dojo.models import Test


class TestWpscanParser(TestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/wpscan/wordpress_no_vuln.json")
        parser = WpscanParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        testfile = open("dojo/unittests/scans/wpscan/wordpress_one_vuln.json")
        parser = WpscanParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        testfile = open("dojo/unittests/scans/wpscan/wordpress_many_vuln.json")
        parser = WpscanParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(3, len(findings))
