from django.test import TestCase
from dojo.tools.choctaw_hog.parser import ChoctawhogParser
from dojo.models import Test


class TestChoctawhogParser(TestCase):
    def test_parse_file_with_no_vuln_has_no_finding(self):
        testfile = open("dojo/unittests/scans/choctaw_hog/no_vuln.json")
        parser = ChoctawhogParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        testfile = open("dojo/unittests/scans/choctaw_hog/one_vuln.json")
        parser = ChoctawhogParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        testfile = open("dojo/unittests/scans/choctaw_hog/many_vulns.json")
        parser = ChoctawhogParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(13, len(findings))
