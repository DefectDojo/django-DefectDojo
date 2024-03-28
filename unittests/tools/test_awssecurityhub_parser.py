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
            finding = findings[0]
            self.assertEqual(finding.component_name, "AwsAccount")

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
            self.assertEqual("CVE-2022-3643 - kernel - Resource: i-11111111111111111", finding.title)
            self.assertEqual("Resource: i-11111111111111111", finding.impact)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2022-3643", finding.unsaved_vulnerability_ids[0])
            self.assertEqual("- Update kernel-4.14.301\n\t- yum update kernel\n", finding.mitigation)
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual('AwsEc2Instance arn:aws:ec2:us-east-1:XXXXXXXXXXXX:i-11111111111111111', endpoint.host)

    def test_inspector_ec2_with_no_vulnerabilities(self):
        with open(get_unit_tests_path() + sample_path("inspector_ec2_cve_no_vulnerabilities.json")) as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual(finding.component_name, "AwsEc2Instance")

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
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual('AwsEc2Instance arn:aws:ec2:eu-central-1:012345678912:instance/i-07c11cc535d830123', endpoint.host)

    def test_inspector_ecr(self):
        with open(get_unit_tests_path() + sample_path("inspector_ecr.json")) as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(7, len(findings))

            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertFalse(finding.is_mitigated)
            self.assertTrue(finding.active)
            self.assertEqual("CVE-2023-2650 - openssl - Image: repo-os/sha256:af965ef68c78374a5f987fce98c0ddfa45801df2395bf012c50b863e65978d74", finding.title)
            self.assertIn("repo-os/sha256:af965ef68c78374a5f987fce98c0ddfa45801df2395bf012c50b863e65978d74", finding.impact)
            self.assertIn("Repository: repo-os", finding.impact)
            self.assertEqual(0.0014, finding.epss_score)
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual('AwsEcrContainerImage arn:aws:ecr:eu-central-1:123456789012:repository/repo-os/sha256:af965ef68c78374a5f987fce98c0ddfa45801df2395bf012c50b863e65978d74', endpoint.host)

    def test_guardduty(self):
        with open(get_unit_tests_path() + sample_path("guardduty.json")) as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(4, len(findings))
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertTrue(finding.active)
            finding = findings[3]
            self.assertEqual("Low", finding.severity)
            self.assertTrue(finding.active)
            self.assertEqual("User AssumedRole : 123123123 is anomalously invoking APIs commonly used in Discovery tactics. - Resource: 123123123", finding.title)
            self.assertEqual("TTPs/Discovery/IAMUser-AnomalousBehavior\nhttps://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html", finding.mitigation)
            endpoint = findings[0].unsaved_endpoints[0]
            self.assertEqual('AwsEc2Instance arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890', endpoint.host)
