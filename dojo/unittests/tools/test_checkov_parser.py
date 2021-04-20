from os import path

from django.test import TestCase
from dojo.models import Test
from dojo.tools.checkov.parser import CheckovParser


class TestCheckovParser(TestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open(path.join(path.dirname(__file__), "scans/checkov/checkov-report-0-vuln.json"))
        parser = CheckovParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        testfile = open(path.join(path.dirname(__file__), "scans/checkov/checkov-report-1-vuln.json"))
        parser = CheckovParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        testfile = open(path.join(path.dirname(__file__), "scans/checkov/checkov-report-many-vuln.json"))
        parser = CheckovParser()
        findings = parser.get_findings(testfile, Test())
        self.assertTrue(len(findings) > 2)
