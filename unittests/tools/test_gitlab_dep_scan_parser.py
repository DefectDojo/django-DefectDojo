from ..dojo_test_case import DojoTestCase, get_unit_tests_path
from dojo.tools.gitlab_dep_scan.parser import GitlabDepScanParser
from dojo.models import Test


class TestGitlabDepScanParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open(
            get_unit_tests_path() + "/scans/gitlab_dep_scan/gl-dependency-scanning-report-0-vuln.json"
        )
        parser = GitlabDepScanParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        testfile = open(
            get_unit_tests_path() + "/scans/gitlab_dep_scan/gl-dependency-scanning-report-1-vuln.json"
        )
        parser = GitlabDepScanParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_two_vuln_has_one_missing_component_(self):
        testfile = open(
            get_unit_tests_path() + "/scans/gitlab_dep_scan/gl-dependency-scanning-report-2-vuln-missing-component.json"
        )
        parser = GitlabDepScanParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(2, len(findings))
        finding = findings[0]
        self.assertEqual(None, finding.component_name)
        self.assertEqual(None, finding.component_version)
        finding = findings[1]
        self.assertEqual("golang.org/x/crypto", finding.component_name)
        self.assertEqual("v0.0.0-20190308221718-c2843e01d9a2", finding.component_version)

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        testfile = open(
            get_unit_tests_path() + "/scans/gitlab_dep_scan/gl-dependency-scanning-report-many-vuln.json"
        )
        parser = GitlabDepScanParser()
        findings = parser.get_findings(testfile, Test())
        self.assertTrue(len(findings) > 2)
