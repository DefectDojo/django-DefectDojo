from django.test import TestCase
from dojo.tools.auditjs.parser import AuditJSParser
from dojo.models import Test


class TestAuditJSParser(TestCase):

    def test_auditjs_parser_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/auditjs/auditjs_zero_vul.json")
        parser = AuditJSParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_auditjs_parser_with_one_criticle_vuln_has_one_findings(self):
        testfile = open("dojo/unittests/scans/auditjs/auditjs_one_vul.json")
        parser = AuditJSParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))
        self.assertEqual("mysql", findings[0].component_name)
        self.assertEqual("2.0.0", findings[0].component_version)
        self.assertEqual(9.5, findings[0].cvssv3_score)
        self.assertEqual("Critical", findings[0].severity)

    def test_auditjs_parser_with_many_vuln_has_many_findings(self):
        testfile = open("dojo/unittests/scans/auditjs/auditjs_many_vul.json")
        parser = AuditJSParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(13, len(findings))
        self.assertEqual("connect", findings[0].component_name)
        self.assertEqual("2.6.0", findings[0].component_version)
        self.assertEqual(5.4, findings[0].cvssv3_score)
