from django.test import TestCase
from dojo.tools.cred_scan.parser import CredScanParser
from dojo.models import Test


class TestCredScanParser(TestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/cred_scan/cred_scan_no_vuln.csv")
        parser = CredScanParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        testfile = open("dojo/unittests/scans/cred_scan/cred_scan_one_vuln.csv")
        parser = CredScanParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        testfile = open("dojo/unittests/scans/cred_scan/cred_scan_many_vuln.csv")
        parser = CredScanParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(3, len(findings))
