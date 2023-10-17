from ..dojo_test_case import DojoTestCase
from dojo.tools.ssh_audit.parser import SSHAuditParser
from dojo.models import Test


class TestSSHAuditParser(DojoTestCase):

    def test_parse_file_with_many_vuln_has_many_findings(self):
        testfile = open("unittests/scans/ssh_audit/many_vulns.json")
        parser = SSHAuditParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(20, len(findings))

    def test_parse_file_with_many_vuln_has_many_findings2(self):
        testfile = open("unittests/scans/ssh_audit/many_vulns2.json")
        parser = SSHAuditParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(12, len(findings))
