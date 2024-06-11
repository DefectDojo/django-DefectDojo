from dojo.models import Test
from dojo.tools.aws_prowler_v3plus.parser import AWSProwlerV3plusParser

from ..dojo_test_case import DojoTestCase


class TestAwsProwlerV3plusParser(DojoTestCase):
    def setup(self, testfile):
        parser = AWSProwlerV3plusParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        return findings

    def test_aws_prowler_parser_with_no_vuln_has_no_findings_json(self):
        findings = self.setup(
            open("unittests/scans/aws_prowler_v3plus/no_vuln.json"))
        self.assertEqual(0, len(findings))

    def test_aws_prowler_parser_with_critical_vuln_has_one_findings_json(self):
        findings = self.setup(
            open("unittests/scans/aws_prowler_v3plus/one_vuln.json"))
        self.assertEqual(1, len(findings))
        self.assertEqual("prowler-aws-acm_certificates_expiration_check-999999999999-us-east-1-api.sandbox.partner.teste.com", findings[0].unique_id_from_tool)
        self.assertIn('Check if ACM Certificates are about to expire in specific days or less', findings[0].description)
        self.assertEqual("arn:aws:acm:us-east-1:999999999999:certificate/ffffffff-0000-0000-0000-000000000000", findings[0].component_name)
        self.assertIn('https://docs.aws.amazon.com/config/latest/developerguide/acm-certificate-expiration-check.html', findings[0].references)

    def test_aws_prowler_parser_with_many_vuln_has_many_findings_json(self):
        findings = self.setup(
            open("unittests/scans/aws_prowler_v3plus/many_vuln.json"))
        self.assertEqual(3, len(findings))
        with self.subTest(i=0):
            self.assertEqual("prowler-aws-acm_certificates_expiration_check-999999999999-us-east-1-api.teste.teste.com", findings[0].unique_id_from_tool)
            self.assertIn('Check if ACM Certificates are about to expire in specific days or less', findings[0].description)
        with self.subTest(i=1):
            self.assertEqual("prowler-aws-accessanalyzer_enabled-999999999999-us-east-1-999999999999", findings[1].unique_id_from_tool)
            self.assertIn('Check if IAM Access Analyzer is enabled', findings[1].description)
        with self.subTest(i=3):
            self.assertEqual("prowler-aws-account_maintain_current_contact_details-999999999999-us-east-1-999999999999", findings[2].unique_id_from_tool)
            self.assertIn('Maintain current contact details.', findings[2].description)

    def test_aws_prowler_parser_with_no_vuln_has_no_findings_ocsf_json(self):
        findings = self.setup(
            open("unittests/scans/aws_prowler_v3plus/no_vuln.ocsf.json"))
        self.assertEqual(0, len(findings))

    def test_aws_prowler_parser_with_critical_vuln_has_one_findings_ocsf_json(self):
        findings = self.setup(
            open("unittests/scans/aws_prowler_v3plus/one_vuln.ocsf.json"))
        self.assertEqual(1, len(findings))
        self.assertEqual("prowler-aws-iam_role_administratoraccess_policy_permissive_trust_relationship-123456789012-us-east-1-myAdministratorExecutionRole", findings[0].unique_id_from_tool)
        self.assertIn('Ensure IAM Roles with attached AdministratorAccess policy have a well defined trust relationship', findings[0].description)
        self.assertEqual("arn:aws:iam::123456789012:role/myAdministratorExecutionRole", findings[0].component_name)
        self.assertIn('https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege', findings[0].references)

    def test_aws_prowler_parser_with_many_vuln_has_many_findings_ocsf_json(self):
        findings = self.setup(
            open("unittests/scans/aws_prowler_v3plus/many_vuln.ocsf.json"))
        self.assertEqual(3, len(findings))
        with self.subTest(i=0):
            self.assertEqual("prowler-aws-iam_role_administratoraccess_policy_permissive_trust_relationship-123456789012-us-east-1-myAdministratorExecutionRole", findings[0].unique_id_from_tool)
            self.assertIn('Ensure IAM Roles with attached AdministratorAccess policy have a well defined trust relationship', findings[0].description)
        with self.subTest(i=1):
            self.assertEqual("prowler-aws-iam_role_cross_account_readonlyaccess_policy-123456789012-us-east-1-AuditRole", findings[1].unique_id_from_tool)
            self.assertIn('Ensure IAM Roles do not have ReadOnlyAccess access for external AWS accounts', findings[1].description)
        with self.subTest(i=3):
            self.assertEqual("prowler-aws-iam_role_permissive_trust_relationship-123456789012-us-east-1-CrossAccountResourceAccessRole", findings[2].unique_id_from_tool)
            self.assertIn('Ensure IAM Roles do not allow assume role from any role of a cross account', findings[2].description)
