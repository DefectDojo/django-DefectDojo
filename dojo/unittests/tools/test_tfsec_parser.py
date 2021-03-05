from django.test import TestCase
from dojo.tools.tfsec.parser import TfsecParser
from dojo.models import Test


class TestTfsecParser(TestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/tfsec/tfsec_no_vuln.csv")
        parser = TfsecParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        testfile = open("dojo/unittests/scans/tfsec/tfsec_one_vuln.csv")
        parser = TfsecParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        testfile = open("dojo/unittests/scans/tfsec/tfsec_many_vulns.csv")
        parser = TfsecParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(9, len(findings))
