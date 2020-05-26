from django.test import TestCase
from dojo.tools.yarn_audit.parser import YarnAuditParser
from dojo.models import Test


class TestYarnAuditParser(TestCase):

    def test_yarn_audit_parser_without_file_has_no_findings(self):
        parser = YarnAuditParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_yarn_audit_parser_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/yarn_audit/yarn_audit_zero_vul.json")
        parser = YarnAuditParser(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(parser.items))

    def test_yarn_audit_parser_with_one_criticle_vuln_has_one_findings(self):
        testfile = open("dojo/unittests/scans/yarn_audit/yarn_audit_one_vul.json")
        parser = YarnAuditParser(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(parser.items))
        self.assertEqual('handlebars', parser.items[0].component_name)
        self.assertEqual('4.5.2', parser.items[0].component_version)

    def test_yarn_audit_parser_with_many_vuln_has_many_findings(self):
        testfile = open("dojo/unittests/scans/yarn_audit/yarn_audit_many_vul.json")
        parser = YarnAuditParser(testfile, Test())
        testfile.close()
        self.assertEqual(3, len(parser.items))

    def test_yarn_audit_parser_empty_with_error(self):
        with self.assertRaises(ValueError) as context:
            testfile = open("dojo/unittests/scans/yarn_audit/empty_with_error.json")
            parser = YarnAuditParser(testfile, Test())
            testfile.close()
            self.assertTrue('yarn audit report contains errors:' in str(context.exception))
            self.assertTrue('ECONNREFUSED' in str(context.exception))
