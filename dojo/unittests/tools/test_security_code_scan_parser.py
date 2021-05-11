from django.test import TestCase
from dojo.models import Test
from dojo.tools.security_code_scan.parser import SecurityCodeScanParser
from collections import Counter


class TestSecurityCodeScanParser(TestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/security_code_scan/nofindings.out")
        parser = SecurityCodeScanParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_17_findings(self):
        testfile = open("dojo/unittests/scans/security_code_scan/manyfindings.out")
        parser = SecurityCodeScanParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(17, len(findings))

    def test_parse_file_severity(self):
        testfile = open("dojo/unittests/scans/security_code_scan/manyfindings.out")
        parser = SecurityCodeScanParser()
        findings = parser.get_findings(testfile, Test())
        sevs = list()

        for finding in findings:
            sevs.append(finding.severity)

        d = Counter(sevs)
        self.assertEqual(1, d['Critical'])
        self.assertEqual(0, d['High'])
        self.assertEqual(15, d['Medium'])
        self.assertEqual(0, d['Low'])
        self.assertEqual(1, d['Info'])
