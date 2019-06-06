from django.test import TestCase
from dojo.tools.npm_audit.parser import NpmAuditParser
from dojo.models import Test


class TestNpmAuditParser(TestCase):

    def test_npm_audit_parser_without_file_has_no_findings(self):
        parser = NpmAuditParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_npm_audit_parser_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/npm_audit_sample/no_vuln.json")
        parser = NpmAuditParser(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(parser.items))

    def test_npm_audit_parser_with_one_criticle_vuln_has_one_findings(self):
        testfile = open("dojo/unittests/scans/npm_audit_sample/one_vuln.json")
        parser = NpmAuditParser(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(parser.items))

    def test_npm_audit_parser_with_many_vuln_has_many_findings(self):
        testfile = open("dojo/unittests/scans/npm_audit_sample/many_vuln.json")
        parser = NpmAuditParser(testfile, Test())
        testfile.close()
        self.assertEqual(5, len(parser.items))
