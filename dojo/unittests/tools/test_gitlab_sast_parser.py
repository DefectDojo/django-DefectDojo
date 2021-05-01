from django.test import TestCase
from dojo.tools.gitlab_sast.parser import GitlabSastParser
from dojo.models import Test


class TestGitlabSastParser(TestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/gitlab_sast/gl-sast-report-0-vuln.json")
        parser = GitlabSastParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        testfile = open("dojo/unittests/scans/gitlab_sast/gl-sast-report-1-vuln.json")
        parser = GitlabSastParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("Password in URL", finding.title)
        self.assertEqual("Critical", finding.severity)

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        testfile = open(
            "dojo/unittests/scans/gitlab_sast/gl-sast-report-many-vuln.json"
        )
        parser = GitlabSastParser()
        findings = parser.get_findings(testfile, Test())
        self.assertTrue(3, len(findings))
        finding = findings[0]
        self.assertEqual("Password in URL", finding.title)
        self.assertEqual("Critical", finding.severity)
        finding = findings[1]
        self.assertEqual("Password in URL", finding.title)
        self.assertEqual("Critical", finding.severity)
        finding = findings[2]
        self.assertEqual("PKCS8 key", finding.title)
        self.assertEqual("Critical", finding.severity)

    def test_parse_file_with_various_confidences(self):
        testfile = open(
            "dojo/unittests/scans/gitlab_sast/gl-sast-report-confidence.json"
        )
        parser = GitlabSastParser()
        findings = parser.get_findings(testfile, Test())
        self.assertTrue(len(findings) == 8)
        for item in findings:
            self.assertTrue(item.cwe is None or isinstance(item.cwe, int))
        finding = findings[3]
        self.assertEqual("Tentative", finding.get_scanner_confidence_text())
        finding = findings[4]
        self.assertEqual("Tentative", finding.get_scanner_confidence_text())
        finding = findings[5]
        self.assertEqual("Firm", finding.get_scanner_confidence_text())
        finding = findings[6]
        self.assertEqual("Firm", finding.get_scanner_confidence_text())
        finding = findings[7]
        self.assertEqual("Certain", finding.get_scanner_confidence_text())

    def test_parse_file_with_various_cwes(self):
        testfile = open("dojo/unittests/scans/gitlab_sast/gl-sast-report-cwe.json")
        parser = GitlabSastParser()
        findings = parser.get_findings(testfile, Test())
        self.assertTrue(len(findings) == 3)
        self.assertEqual(79, findings[0].cwe)
        self.assertEqual(89, findings[1].cwe)
        self.assertEqual(None, findings[2].cwe)

    def test_parse_file_issue4336(self):
        testfile = open("dojo/unittests/scans/gitlab_sast/gl-sast-report_issue4344.json")
        parser = GitlabSastParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("[None severity] Potential XSS vulnerability", finding.title)
