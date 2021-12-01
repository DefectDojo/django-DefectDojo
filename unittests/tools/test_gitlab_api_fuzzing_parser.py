from ..dojo_test_case import DojoTestCase, get_unit_tests_path
from dojo.tools.gitlab_api_fuzzing.parser import GitlabAPIFuzzingParser
from dojo.models import Test


class TestGitlabAPIFuzzingParser(DojoTestCase):
    def test_gitlab_api_fuzzing_parser_with_no_vuln_has_no_findings(self):
        with open(
            get_unit_tests_path() + "/scans/gitlab_api_fuzzing/gitlab_api_fuzzing_0_vuln.json"
        ) as testfile:
            parser = GitlabAPIFuzzingParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.assertEqual(0, len(findings))

    def test_gitlab_api_fuzzing_parser_with_one_criticle_vuln_has_one_findings(self):
        with open(
            get_unit_tests_path() + "/scans/gitlab_api_fuzzing/gitlab_api_fuzzing_1_vuln.json"
        ) as testfile:
            parser = GitlabAPIFuzzingParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            first_finding = findings[0]
            self.assertEqual(first_finding.title, "name")
            self.assertEqual(
                first_finding.description,
                "coverage_fuzzing\nIndex-out-of-range\ngo-fuzzing-example.ParseComplex.func6\ngo-fuzzing-example.ParseComplex\ngo-fuzzing-example.Fuzz\n",
            )
            self.assertEqual(
                first_finding.unique_id_from_tool,
                "c83603d0befefe01644abdda1abbfaac842fccbabfbe336db9f370386e40f702",
            )

    def test_gitlab_api_fuzzing_parser_with_invalid_json(self):
        with open(
            get_unit_tests_path() + "/scans/gitlab_api_fuzzing/gitlab_api_fuzzing_invalid.json"
        ) as testfile:
            # Something is wrong with JSON file
            with self.assertRaises((KeyError, ValueError)):
                parser = GitlabAPIFuzzingParser()
                parser.get_findings(testfile, Test())
