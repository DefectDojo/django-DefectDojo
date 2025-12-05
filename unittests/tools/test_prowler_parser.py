from django.test import TestCase
from dojo.tools.prowler.parser import ProwlerParser
from dojo.models import Test


class TestProwlerParser(TestCase):
    # TODO: Write test for:
    # AWS CSV
    # JSON CSV
    # Azure CSV
    # Azure CSV
    # GCP CSV
    # GCP CSV
    # Kubernetes CSV
    # Kubernetes CSV

    def test_prowler_parser_json_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/prowler/prowler_zero_vul.json")
        parser = ProwlerParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_prowler_parser_csv_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/prowler/prowler_zero_vul.csv")
        parser = ProwlerParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_prowler_parser_aws_csv_file_with_multiple_vulnerabilities(self):
        with open("unittests/scans/prowler/example_output_aws.csv") as testfile:
            parser = ProwlerParser()
            findings = parser.get_findings(testfile, Test())
            items = findings
            self.assertEqual(4, len(items))

            with self.subTest(i=0):
                self.assertEqual(items[0].title, "Check if IAM Access Analyzer is enabled")
                self.assertEqual(items[0].severity, "Low")
                description = (
                    "**Cloud Type** : AWS\n\n"
                    + "**Description** : Check if IAM Access Analyzer is enabled\n\n"
                    + "**Service Name** : accessanalyzer\n\n"
                    + "**Status Detail** : IAM Access Analyzer in account <account_uid> is not enabled.\n\n"
                    + "**Finding Created Time** : 2025-02-14 14:27:03.913874\n\n"
                    + "**Region** : <region>\n\n"
                    + "**Notes** : \n\n"
                    + "**Related URL** : https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html\n\n"
                    + "**Additional URLs** : https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html | https://aws.amazon.com/iam/features/analyze-access/"
                )

                self.assertEqual(items[0].description, description)
