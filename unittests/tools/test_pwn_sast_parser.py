from ..dojo_test_case import DojoTestCase
from dojo.tools.pwn_sast.parser import PWNSASTParser
from dojo.models import Test


class TestPWNSASTParser(DojoTestCase):

    def test_parse_no_findings(self):
        testfile = open("unittests/scans/pwn_sast/no_findings.json")
        parser = PWNSASTParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        testfile = open("unittests/scans/pwn_sast/one_finding.json")
        parser = PWNSASTParser()
        findings = parser.get_findings(testfile, Test())
        self.assertIsInstance(findings, list)
        self.assertEqual(1, len(findings))

    def test_parse_many_finding(self):
        testfile = open("unittests/scans/pwn_sast/many_findings.json")
        parser = PWNSASTParser()
        findings = parser.get_findings(testfile, Test())
        self.assertIsInstance(findings, list)
        self.assertEqual(3, len(findings))

    def test_one_dup_finding(self):
        testfile = open("unittests/scans/pwn_sast/one_dup_finding.json")
        parser = PWNSASTParser()
        findings = parser.get_findings(testfile, Test())
        self.assertIsInstance(findings, list)
        self.assertEqual(1, len(findings))

    def test_title_is_not_none(self):
        testfile = open("unittests/scans/pwn_sast/one_finding.json")
        parser = PWNSASTParser()
        findings = parser.get_findings(testfile, Test())
        self.assertIsInstance(findings, list)
        for finding in findings:
            self.assertIsNotNone(finding.title)
