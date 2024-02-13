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
        self.assertEqual(findings[0].title, "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2_CVE-2021-41617")
        self.assertEqual(findings[1].title, "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2_CVE-2020-15778")
        self.assertEqual(findings[0].severity, "High")
        self.assertEqual(findings[13].severity, "Medium")

    def test_parse_file_with_many_vuln_has_many_findings2(self):
        testfile = open("unittests/scans/ssh_audit/many_vulns2.json")
        parser = SSHAuditParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(12, len(findings))
        self.assertEqual(findings[0].title, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4_ecdh-sha2-nistp256")
        self.assertEqual(findings[1].title, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4_ecdh-sha2-nistp384")
        self.assertEqual(findings[0].severity, "High")
        self.assertEqual(findings[9].severity, "Medium")

    def test_parse_file_with_many_vuln_bug_fix(self):
        testfile = open("unittests/scans/ssh_audit/bug_fix.json")
        parser = SSHAuditParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(13, len(findings))
        self.assertEqual(findings[0].title, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.5_ecdh-sha2-nistp256")
        self.assertEqual(findings[1].title, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.5_ecdh-sha2-nistp384")
        self.assertEqual(findings[0].severity, "High")
