from ..dojo_test_case import DojoParserTestCase
from dojo.tools.eslint.parser import ESLintParser
from dojo.models import Test


class TestESLintParser(DojoParserTestCase):

    parser = ESLintParser()

    def test_parse_file_has_two_findings(self):
        testfile = open("unittests/scans/eslint/scan.json")
        findings = self.parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(2, len(findings))

    def test_parse_empty_file(self):
        testfile = open("unittests/scans/eslint/empty.json")
        findings = self.parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parse_file_with_no_finding(self):
        testfile = open("unittests/scans/eslint/no_finding.json")
        findings = self.parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))
