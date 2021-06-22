from django.test import TestCase
from dojo.tools.checkov.parser import CheckovParser
from dojo.models import Test


class TestCheckovParser(TestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/checkov/checkov-report-0-vuln.json")
        parser = CheckovParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        testfile = open("dojo/unittests/scans/checkov/checkov-report-1-vuln.json")
        parser = CheckovParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        testfile = open("dojo/unittests/scans/checkov/checkov-report-many-vuln.json")
        parser = CheckovParser()
        findings = parser.get_findings(testfile, Test())
        self.assertTrue(len(findings) > 2)

    def test_parse_file_with_multiple_check_type_has_multiple_check_type(self):
        testfile = open("dojo/unittests/scans/checkov/checkov-multiple-check_type.json")
        parser = CheckovParser()
        findings = parser.get_findings(testfile, Test())
        self.assertTrue('Check Type: terraform' in findings[0].description)
        self.assertTrue('Check Type: dockerfile' in findings[11].description)
