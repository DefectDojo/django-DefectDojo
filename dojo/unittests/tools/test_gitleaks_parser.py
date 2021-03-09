from django.test import TestCase
from dojo.tools.gitleaks.parser import GitleaksParser
from dojo.models import Test


class TestGitleaksParser(TestCase):

    def test_parse_file_with_one_finding(self):
        testfile = open("dojo/unittests/scans/gitleaks/data_one.json")
        parser = GitleaksParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_finding(self):
        testfile = open("dojo/unittests/scans/gitleaks/data_many.json")
        parser = GitleaksParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(2, len(findings))
