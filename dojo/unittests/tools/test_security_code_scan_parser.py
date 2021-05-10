from django.test import TestCase
from dojo.models import Test
from dojo.tools.security_code_scan.parser import SecurityCodeScanParser


class TestSecurityCodeScanParser(TestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/security_code_scan/nofindings.report")
        parser = SecurityCodeScanParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))