from django.test import TestCase
from dojo.tools.gitlab_sast.parser import GitlabSastReportParser
from dojo.models import Test


class TestGitlabSastReportParser(TestCase):

    def test_parse_without_file_has_no_findings(self):
        parser = GitlabSastReportParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/gitlab_sast/gl-sast-report-0-vuln.json")
        parser = GitlabSastReportParser(testfile, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        testfile = open("dojo/unittests/scans/gitlab_sast/gl-sast-report-1-vuln.json")
        parser = GitlabSastReportParser(testfile, Test())
        self.assertEqual(1, len(parser.items))

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        testfile = open("dojo/unittests/scans/gitlab_sast/gl-sast-report-many-vuln.json")
        parser = GitlabSastReportParser(testfile, Test())
        self.assertTrue(len(parser.items) > 2)
