from ..dojo_test_case import DojoTestCase
from dojo.tools.aws_prowler_v3.parser import AWSProwlerV3Parser
from dojo.models import Test


class TestAwsProwlerV3Parser(DojoTestCase):
    def setup(self, testfile):
        parser = AWSProwlerV3Parser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        return findings

    def test_aws_prowler_parser_with_no_vuln_has_no_findings_json(self):
        findings = self.setup(
            open("unittests/scans/aws_prowler_v3/no_vuln.json"))
        self.assertEqual(0, len(findings))

    def test_aws_prowler_parser_with_critical_vuln_has_one_findings_json(self):
        findings = self.setup(
            open("unittests/scans/aws_prowler_v3/one_vuln.json"))
        self.assertEqual(1, len(findings))
        self.assertEqual("prowler-aws-acm_certificates_expiration_check-999999999999-us-east-1-api.sandbox.partner.teste.com", findings[0].unique_id_from_tool)
        self.assertIn('Check if ACM Certificates are about to expire in specific days or less', findings[0].description)
        self.assertEqual("arn:aws:acm:us-east-1:999999999999:certificate/ffffffff-0000-0000-0000-000000000000", findings[0].component_name)
        self.assertIn('https://docs.aws.amazon.com/config/latest/developerguide/acm-certificate-expiration-check.html', findings[0].references)

    def test_aws_prowler_parser_with_many_vuln_has_many_findings_json(self):
        findings = self.setup(
            open("unittests/scans/aws_prowler_v3/many_vuln.json"))
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
