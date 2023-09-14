import os.path

from ..dojo_test_case import DojoTestCase, get_unit_tests_path
from dojo.tools.awssecurityhub.parser import AwsSecurityHubParser
from dojo.models import Test


def sample_path(file_name: str):
    return os.path.join("/scans/awssecurityhub", file_name)


class TestAwsSecurityHubParser(DojoTestCase):

    def test_one_finding(self):
        with open(get_unit_tests_path() + sample_path("config_one_finding.json")) as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Informational", finding.severity)
            self.assertTrue(finding.is_mitigated)
            self.assertFalse(finding.active)
            self.assertEqual("https://docs.aws.amazon.com/console/securityhub/IAM.5/remediation", finding.references)

    def test_one_finding_active(self):
        with open(get_unit_tests_path() + sample_path("config_one_finding_active.json")) as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertFalse(finding.is_mitigated)
            self.assertTrue(finding.active)

    def test_many_findings(self):
        with open(get_unit_tests_path() + sample_path("config_many_findings.json")) as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(3, len(findings))

    def test_repeated_findings(self):
        with open(get_unit_tests_path() + sample_path("config_repeated_findings.json")) as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(1, len(findings))

    def test_unique_id(self):
        with open(get_unit_tests_path() + sample_path("config_one_finding.json")) as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(
                "arn:aws:securityhub:us-east-1:012345678912:subscription/aws-foundational-security-best-practices/v/1.0.0/IAM.5/finding/de861909-2d26-4e45-bd86-19d2ab6ceef1",
                findings[0].unique_id_from_tool
            )

    def test_inspector_ec2(self):
        with open(get_unit_tests_path() + sample_path("inspector_ec2_cve.json")) as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(5, len(findings))
            finding = findings[0]
            self.assertIn("CVE-2022-3643", finding.title)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2022-3643", finding.unsaved_vulnerability_ids[0])
            self.assertEqual("- Update kernel-4.14.301\n\t- yum update kernel\n", finding.mitigation)

    def test_inspector_ec2_with_no_vulnerabilities(self):
        with open(get_unit_tests_path() + sample_path("inspector_ec2_cve_no_vulnerabilities.json")) as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(1, len(findings))

    def test_inspector_ec2_ghsa(self):
        with open(get_unit_tests_path() + sample_path("inspector_ec2_ghsa.json")) as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertFalse(finding.is_mitigated)
            self.assertTrue(finding.active)
            self.assertIn("GHSA-p98r-538v-jgw5", finding.title)
            self.assertSetEqual({"CVE-2023-34256", "GHSA-p98r-538v-jgw5"}, set(finding.unsaved_vulnerability_ids))
            self.assertEqual("https://github.com/bottlerocket-os/bottlerocket/security/advisories/GHSA-p98r-538v-jgw5", finding.references)
