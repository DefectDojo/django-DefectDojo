from os import path
from ..dojo_test_case import DojoTestCase
from dojo.tools.npm_audit_7_plus import NpmAudit7PlusParser
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

    def test_npm_audit_7_plus_parser_with_one_vuln_has_one_findings(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/npm_audit_7_plus/many_vulns.json"))
        parser = NpmAudit7PlusParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(6, len(findings))
