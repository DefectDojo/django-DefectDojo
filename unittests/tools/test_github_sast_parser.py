import io

from dojo.models import Test
from dojo.tools.github_sast.parser import GithubSASTParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestGithubSASTParser(DojoTestCase):
    def test_parse_file_with_no_vuln_has_no_findings(self):
        """Empty list should yield no findings"""
        with (get_unit_tests_scans_path("github_sast") / "github_sast_zero_vul.json").open(
            encoding="utf-8",
        ) as testfile:
            parser = GithubSASTParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_parsed_correctly(self):
        """Single vulnerability entry parsed correctly"""
        with (get_unit_tests_scans_path("github_sast") / "github_sast_one_vul.json").open(encoding="utf-8") as testfile:
            parser = GithubSASTParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            for ep in getattr(finding, "unsaved_endpoints", []):
                ep.clean()

            expected_title = "Clear-text storage of sensitive information (py/clear-text-storage-sensitive-data)"
            self.assertEqual(expected_title, finding.title)
            self.assertEqual("src/file.py", finding.file_path)
            self.assertEqual(42, finding.line)
            self.assertEqual("py/clear-text-storage-sensitive-data", finding.vuln_id_from_tool)
            self.assertEqual("High", finding.severity)
            self.assertEqual("https://github.com/OWASP/test-repository/security/code-scanning/35", finding.url)
            self.assertIn("This expression stores sensitive data", finding.description)

    def test_parse_file_with_multiple_vulns_has_multiple_findings(self):
        """Multiple entries produce corresponding findings"""
        with (get_unit_tests_scans_path("github_sast") / "github_sast_many_vul.json").open(
            encoding="utf-8",
        ) as testfile:
            parser = GithubSASTParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
            lines = sorted(f.line for f in findings)
            self.assertListEqual([42, 78], lines)

    def test_parse_file_invalid_format_raises(self):
        """Non-list JSON should raise"""
        bad_json = io.StringIO('{"not": "a list"}')
        parser = GithubSASTParser()
        with self.assertRaises(TypeError):
            parser.get_findings(bad_json, Test())
