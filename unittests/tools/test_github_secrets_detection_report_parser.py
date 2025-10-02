import io

from dojo.models import Test
from dojo.tools.github_secrets_detection_report.parser import GithubSecretsDetectionReportParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestGithubSecretsDetectionReportParser(DojoTestCase):
    def test_parse_file_with_no_vuln_has_no_findings(self):
        """Empty list should yield no findings"""
        with (
            get_unit_tests_scans_path("github_secrets_detection_report")
            / "github_secrets_detection_report_zero_vul.json"
        ).open(
            encoding="utf-8",
        ) as testfile:
            parser = GithubSecretsDetectionReportParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_parsed_correctly(self):
        """Single secret alert entry parsed correctly"""
        with (
            get_unit_tests_scans_path("github_secrets_detection_report")
            / "github_secrets_detection_report_one_vul.json"
        ).open(encoding="utf-8") as testfile:
            parser = GithubSecretsDetectionReportParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            for ep in getattr(finding, "unsaved_endpoints", []):
                ep.clean()

            expected_title = "Exposed Secret Detected: Adafruit IO Key"
            self.assertEqual(expected_title, finding.title)
            self.assertEqual("/example/secrets.txt", finding.file_path)
            self.assertEqual(1, finding.line)
            self.assertEqual("2", finding.vuln_id_from_tool)
            self.assertEqual("Info", finding.severity)
            self.assertEqual("https://github.com/owner/private-repo/security/secret-scanning/2", finding.url)
            self.assertIn("**Secret Type**: Adafruit IO Key", finding.description)
            self.assertIn("**Alert State**: resolved", finding.description)
            self.assertIn("**Repository**: octocat/Hello-World", finding.description)
            self.assertIn("**Resolution**: false_positive", finding.description)
            self.assertIn("**Push Protection Bypassed**: True", finding.description)
            self.assertIn("**Validity**: active", finding.description)
            self.assertIn("**Publicly Leaked**: No", finding.description)
            self.assertIn("**Multi-Repository**: No", finding.description)

    def test_parse_file_with_multiple_vulns_has_multiple_findings(self):
        """Multiple entries produce corresponding findings"""
        with (
            get_unit_tests_scans_path("github_secrets_detection_report")
            / "github_secrets_detection_report_many_vul.json"
        ).open(
            encoding="utf-8",
        ) as testfile:
            parser = GithubSecretsDetectionReportParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

            # Test first finding (resolved false positive)
            finding1 = findings[0]
            self.assertEqual("Exposed Secret Detected: Adafruit IO Key", finding1.title)
            self.assertEqual("Info", finding1.severity)
            self.assertEqual("2", finding1.vuln_id_from_tool)
            self.assertIn("**Resolution**: false_positive", finding1.description)

            # Test second finding (open AWS key)
            finding2 = findings[1]
            self.assertEqual("Exposed Secret Detected: AWS Access Key ID", finding2.title)
            self.assertEqual("Critical", finding2.severity)
            self.assertEqual("3", finding2.vuln_id_from_tool)
            self.assertIn("**Alert State**: open", finding2.description)
            self.assertIn("**Publicly Leaked**: Yes", finding2.description)

            # Test third finding (resolved revoked token)
            finding3 = findings[2]
            self.assertEqual("Exposed Secret Detected: GitHub Personal Access Token", finding3.title)
            self.assertEqual("Info", finding3.severity)
            self.assertEqual("4", finding3.vuln_id_from_tool)
            self.assertIn("**Resolution**: revoked", finding3.description)
            self.assertIn("**Multi-Repository**: Yes", finding3.description)

    def test_parse_file_invalid_format_raises(self):
        """Non-list JSON should raise"""
        bad_json = io.StringIO('{"not": "a list"}')
        parser = GithubSecretsDetectionReportParser()
        with self.assertRaises(TypeError):
            parser.get_findings(bad_json, Test())

    def test_severity_assignment(self):
        """Test severity assignment logic"""
        with (
            get_unit_tests_scans_path("github_secrets_detection_report")
            / "github_secrets_detection_report_many_vul.json"
        ).open(
            encoding="utf-8",
        ) as testfile:
            parser = GithubSecretsDetectionReportParser()
            findings = parser.get_findings(testfile, Test())

            # Check severity assignments
            severities = [finding.severity for finding in findings]
            self.assertIn("Info", severities)  # resolved findings
            self.assertIn("Critical", severities)  # active + publicly leaked
            self.assertEqual(3, len(severities))

    def test_file_path_and_line_assignment(self):
        """Test file path and line number extraction"""
        with (
            get_unit_tests_scans_path("github_secrets_detection_report")
            / "github_secrets_detection_report_one_vul.json"
        ).open(
            encoding="utf-8",
        ) as testfile:
            parser = GithubSecretsDetectionReportParser()
            findings = parser.get_findings(testfile, Test())

            finding = findings[0]
            self.assertEqual("/example/secrets.txt", finding.file_path)
            self.assertEqual(1, finding.line)

    def test_url_setting(self):
        """Test URL assignment from GitHub alert"""
        with (
            get_unit_tests_scans_path("github_secrets_detection_report")
            / "github_secrets_detection_report_one_vul.json"
        ).open(
            encoding="utf-8",
        ) as testfile:
            parser = GithubSecretsDetectionReportParser()
            findings = parser.get_findings(testfile, Test())

            finding = findings[0]
            self.assertEqual("https://github.com/owner/private-repo/security/secret-scanning/2", finding.url)
