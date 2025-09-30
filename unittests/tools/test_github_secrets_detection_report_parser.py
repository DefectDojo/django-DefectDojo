from django.test import TestCase
from dojo.tools.github_secrets_detection_report.parser import GithubSecretsDetectionReportParser
from dojo.models import Test


class TestGithubSecretsDetectionReportParser(TestCase):

    def test_github_secrets_detection_report_parser_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/github_secrets_detection_report/github_secrets_detection_report_zero_vul.json")
        parser = GithubSecretsDetectionReportParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_github_secrets_detection_report_parser_with_one_vuln_has_one_finding(self):
        testfile = open("unittests/scans/github_secrets_detection_report/github_secrets_detection_report_one_vul.json")
        parser = GithubSecretsDetectionReportParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        
        self.assertEqual(1, len(findings))
        
        finding = findings[0]
        self.assertEqual("Exposed Secret Detected: Adafruit IO Key", finding.title)
        self.assertEqual("Info", finding.severity)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual("2", finding.vuln_id_from_tool)
        self.assertIn("**Secret Type**: Adafruit IO Key", finding.description)
        self.assertIn("**Alert State**: resolved", finding.description)
        self.assertIn("**Repository**: octocat/Hello-World", finding.description)
        self.assertIn("**File Path**: /example/secrets.txt", finding.description)
        self.assertIn("**Line**: 1", finding.description)
        self.assertIn("**Resolution**: false_positive", finding.description)
        self.assertIn("**Push Protection Bypassed**: True", finding.description)
        self.assertIn("**Validity**: active", finding.description)
        self.assertIn("**Publicly Leaked**: No", finding.description)
        self.assertIn("**Multi-Repository**: No", finding.description)

    def test_github_secrets_detection_report_parser_with_many_vuln_has_many_findings(self):
        testfile = open("unittests/scans/github_secrets_detection_report/github_secrets_detection_report_many_vul.json")
        parser = GithubSecretsDetectionReportParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        
        self.assertEqual(3, len(findings))
        
        # Test first finding (resolved false positive)
        finding1 = findings[0]
        self.assertEqual("Exposed Secret Detected: Adafruit IO Key", finding1.title)
        self.assertEqual("Info", finding1.severity)  # resolved false positive
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
        self.assertEqual("Info", finding3.severity)  # resolved
        self.assertEqual("4", finding3.vuln_id_from_tool)
        self.assertIn("**Resolution**: revoked", finding3.description)
        self.assertIn("**Multi-Repository**: Yes", finding3.description)

    def test_github_secrets_detection_report_parser_invalid_format(self):
        with self.assertRaises(TypeError) as context:
            testfile = open("unittests/scans/github_secrets_detection_report/empty.json")
            parser = GithubSecretsDetectionReportParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
        
        self.assertIn("Invalid GitHub secrets detection report format", str(context.exception))

    def test_github_secrets_detection_report_parser_severity_assignment(self):
        testfile = open("unittests/scans/github_secrets_detection_report/github_secrets_detection_report_many_vul.json")
        parser = GithubSecretsDetectionReportParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        
        # Check severity assignments
        severities = [finding.severity for finding in findings]
        self.assertIn("Info", severities)
        self.assertIn("Critical", severities)
        self.assertEqual(3, len(severities))

    def test_github_secrets_detection_report_parser_file_path_and_line(self):
        testfile = open("unittests/scans/github_secrets_detection_report/github_secrets_detection_report_one_vul.json")
        parser = GithubSecretsDetectionReportParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        
        finding = findings[0]
        self.assertEqual("/example/secrets.txt", finding.file_path)
        self.assertEqual(1, finding.line)

    def test_github_secrets_detection_report_parser_url_setting(self):
        testfile = open("unittests/scans/github_secrets_detection_report/github_secrets_detection_report_one_vul.json")
        parser = GithubSecretsDetectionReportParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        
        finding = findings[0]
        self.assertIn("https://github.com/owner/private-repo/security/secret-scanning/2", finding.url)
