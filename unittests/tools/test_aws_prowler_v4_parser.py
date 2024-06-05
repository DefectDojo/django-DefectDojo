from dojo.models import Test
from dojo.tools.aws_prowler_v4.parser import AWSProwlerV4Parser

from ..dojo_test_case import DojoTestCase


class TestAwsProwlerV4Parser(DojoTestCase):
    def setup(self, testfile):
        parser = AWSProwlerV4Parser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        return findings

    def test_aws_prowler_parser_with_no_vuln_has_no_findings_json(self):
        findings = self.setup(
            open("unittests/scans/aws_prowler_v4/no_vuln.json"))
        self.assertEqual(0, len(findings))

    def test_aws_prowler_parser_with_critical_vuln_has_one_findings_json(self):
        findings = self.setup(
            open("unittests/scans/aws_prowler_v4/one_vuln.json"))
        self.assertEqual(1, len(findings))
        self.assertEqual("prowler-aws-iam_role_administratoraccess_policy_permissive_trust_relationship-123456789012-us-east-1-myAdministratorExecutionRole", findings[0].unique_id_from_tool)
        self.assertIn('Ensure IAM Roles with attached AdministratorAccess policy have a well defined trust relationship', findings[0].description)
        self.assertEqual("arn:aws:iam::123456789012:role/myAdministratorExecutionRole", findings[0].component_name)
        self.assertIn('https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege', findings[0].references)

    def test_aws_prowler_parser_with_many_vuln_has_many_findings_json(self):
        findings = self.setup(
            open("unittests/scans/aws_prowler_v4/many_vuln.json"))
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
