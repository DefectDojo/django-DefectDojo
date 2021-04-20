from os import path

from django.test import TestCase
from dojo.models import Test
from dojo.tools.gitleaks.parser import GitleaksParser


class TestGitleaksParser(TestCase):

    def test_parse_file_with_no_findings(self):
        testfile = open(path.join(path.dirname(__file__), "scans/gitleaks/no_findings.json"))
        parser = GitleaksParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_finding(self):
        testfile = open(path.join(path.dirname(__file__), "scans/gitleaks/data_one.json"))
        parser = GitleaksParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_finding(self):
        testfile = open(path.join(path.dirname(__file__), "scans/gitleaks/data_many.json"))
        parser = GitleaksParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(2, len(findings))
