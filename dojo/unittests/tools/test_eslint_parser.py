from django.test import TestCase
from dojo.tools.eslint.parser import ESLintParser
from dojo.models import Test


class TestESLintParser(TestCase):
    def test_parse_file_has_two_findings(self):
        testfile = open("dojo/unittests/scans/eslint/scan.json")
        parser = ESLintParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(2, len(findings))

    def test_parse_empty_file(self):
        testfile = open("dojo/unittests/scans/eslint/empty.json")
        parser = ESLintParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parse_file_with_no_finding(self):
        testfile = open("dojo/unittests/scans/eslint/no_finding.json")
        parser = ESLintParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))
