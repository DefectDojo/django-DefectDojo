from os import path
from ..dojo_test_case import DojoTestCase
from dojo.tools.npm_audit_7_plus.parser import NpmAudit7PlusParser
from dojo.models import Test


class TestNpmAudit7PlusParser(DojoTestCase):
    def test_npm_audit_7_plus_parser_with_no_vuln_has_no_findings(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/npm_audit_7_plus/no_vuln.json"))
        parser = NpmAudit7PlusParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_npm_audit_7_plus_parser_with_one_vuln_has_one_findings(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/npm_audit_7_plus/one_vuln.json"))
        parser = NpmAudit7PlusParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("High", finding.severity)
            self.assertEqual(400, finding.cwe)
            self.assertIsNotNone(finding.description)
            self.assertGreater(len(finding.description), 0)
            self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", finding.cvssv3)

    def test_npm_audit_7_plus_parser_with_many_vuln_has_many_findings(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/npm_audit_7_plus/many_vulns.json"))
        parser = NpmAudit7PlusParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(6, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(1035, finding.cwe)
            self.assertIsNotNone(finding.description)
            self.assertGreater(len(finding.description), 0)
            self.assertEqual("@vercel/fun", finding.title)
