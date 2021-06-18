from django.test import TestCase
from dojo.tools.gitlab_api_fuzzing.parser import GitlabAPIFuzzingParser
from dojo.models import Test


class TestGitlabAPIFuzzingParser(TestCase):

    def test_gitlab_api_fuzzing_parser_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/gitlab_api_fuzzing/gitlab_api_fuzzing_0_vuln.json")
        parser = GitlabAPIFuzzingParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_gitlab_api_fuzzing_parser_with_one_criticle_vuln_has_one_findings(self):
        testfile = open("dojo/unittests/scans/gitlab_api_fuzzing/gitlab_api_fuzzing_1_vuln.json")
        parser = GitlabAPIFuzzingParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))
        self.assertEqual("handlebars", findings[0].component_name)
        self.assertEqual("4.5.2", findings[0].component_version)
