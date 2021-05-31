from django.test import TestCase
from dojo.tools.gitlab_dast.parser import GitlabDastParser
# from dojo.tools.{ cookiecutter.tool_name }}.parser import GitLab DAST ReportParser
from dojo.models import Test


class TestGitlabSastParser(TestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/gitlab_dast/gl-dast-report-0-vuln.json")
        parser = GitlabDastParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        testfile = open("dojo/unittests/scans/gitlab_dast/gl-dast-report-1-vuln.json")
        parser = GitlabDastParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("Password in URL", finding.title)
        self.assertEqual("Critical", finding.severity)

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        testfile = open(
            "dojo/unittests/scans/gitlab_dast/gl-dast-report-many-vuln.json"
        )
        parser = GitlabDastParser()
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
