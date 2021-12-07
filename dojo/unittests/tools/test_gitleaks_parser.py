from django.test import TestCase
from dojo.tools.gitleaks.parser import GitleaksParser
from dojo.models import Test


class TestGitleaksParser(TestCase):

    def test_parse_file_with_no_findings(self):
        testfile = open("dojo/unittests/scans/gitleaks/no_findings.json")
        parser = GitleaksParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_finding(self):
        testfile = open("dojo/unittests/scans/gitleaks/data_one.json")
        parser = GitleaksParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Hard Coded Asymmetric Private Key", finding.title)
            self.assertEqual("cert-key.pem", finding.file_path)
            self.assertIsNone(finding.line)  # some old version don't have this data
            self.assertIn("AsymmetricPrivateKey", finding.unsaved_tags)

    def test_parse_file_with_multiple_finding(self):
        testfile = open("dojo/unittests/scans/gitleaks/data_many.json")
        parser = GitleaksParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(2, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Hard Coded Github", finding.title)
            self.assertEqual(".bashrc", finding.file_path)
            self.assertIsNone(finding.line)  # some old version don't have this data
            self.assertIn("Github", finding.unsaved_tags)

    def test_parse_file_with_multiple_redacted_finding(self):
        testfile = open("dojo/unittests/scans/gitleaks/redacted_data_many.json")
        parser = GitleaksParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(6, len(findings))

    def test_parse_file_from_issue4336(self):
        testfile = open("dojo/unittests/scans/gitleaks/issue4336.json")
        parser = GitleaksParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Hard Coded Twitter Client ID", finding.title)
            self.assertEqual("README.md", finding.file_path)
            self.assertEqual(23, finding.line)

    def test_parse_file_from_version_7_5_0(self):
        testfile = open("dojo/unittests/scans/gitleaks/version_7.5.0.json")
        parser = GitleaksParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(4, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Hard Coded AWS Access Key", finding.title)
            self.assertEqual("dojo/unittests/scans/gitlab_secret_detection_report/gitlab_secret_detection_report_1_vuln.json", finding.file_path)
            self.assertEqual(13, finding.line)
            self.assertIn("key", finding.unsaved_tags)
            self.assertIn("AWS", finding.unsaved_tags)
        with self.subTest(i=1):
            finding = findings[1]
            self.assertEqual("Hard Coded Asymmetric Private Key", finding.title)
            self.assertEqual("dojo/unittests/scans/gitlab_secret_detection_report/gitlab_secret_detection_report_3_vuln.json", finding.file_path)
            self.assertEqual(13, finding.line)
            self.assertIn("AsymmetricPrivateKey", finding.unsaved_tags)
        with self.subTest(i=2):
            finding = findings[2]
            self.assertEqual("Hard Coded AWS Access Key", finding.title)
            self.assertEqual("dojo/unittests/scans/gitlab_secret_detection_report/gitlab_secret_detection_report_3_vuln.json", finding.file_path)
            self.assertEqual(44, finding.line)
            self.assertIn("AWS", finding.unsaved_tags)
        with self.subTest(i=3):
            finding = findings[3]
            self.assertEqual("Hard Coded AWS Access Key", finding.title)
            self.assertEqual("dojo/unittests/tools/test_gitlab_secret_detection_report_parser.py", finding.file_path)
            self.assertEqual(37, finding.line)
            self.assertIn("AWS", finding.unsaved_tags)
