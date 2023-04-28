from ..dojo_test_case import DojoTestCase
from dojo.tools.aws_prowler_v3.parser import AWSProwlerJsonV3Parser
from dojo.models import Test


class TestAwsProwlerParser(DojoTestCase):
    def setup(self, testfile):
        parser = AWSProwlerJsonV3Parser()
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
        self.assertEqual("prowler-aws-acm_certificates_expiration_check-999999999999-us-east-1-api.sandbox.partner.teste.com", findings[0].FindingUniqueId)
        self.assertEqual('Check if ACM Certificates are about to expire in specific days or less', findings[0].Description)
        self.assertEqual('us-east-1', findings[0].Region)
        self.assertEqual('https://docs.aws.amazon.com/config/latest/developerguide/acm-certificate-expiration-check.html', findings[0].Remediation.Recommendation.Url)

    def test_aws_prowler_parser_with_many_vuln_has_many_findings_json(self):
        findings = self.setup(
            open("unittests/scans/aws_prowler_v3/many_vuln.json"))
        self.assertEqual(4, len(findings))
        with self.subTest(i=0):
            self.assertEqual("prowler-aws-acm_certificates_expiration_check-999999999999-us-east-1-api.sandbox.partner.teste.com", findings[0].FindingUniqueId)
            self.assertEqual('Check if ACM Certificates are about to expire in specific days or less', findings[0].Description)
            self.assertEqual('us-east-1', findings[0].Region)
        with self.subTest(i=1):
            self.assertEqual("prowler-aws-accessanalyzer_enabled-999999999999-us-east-1-999999999999", findings[0].FindingUniqueId)
            self.assertEqual('Check if IAM Access Analyzer is enabled', findings[0].Description)
            self.assertEqual('us-east-1', findings[0].Region)
        with self.subTest(i=2):
            self.assertEqual("prowler-aws-accessanalyzer_enabled_without_findings-999999999999-us-east-1-999999999999", findings[0].FindingUniqueId)
            self.assertEqual('Check if IAM Access Analyzer is enabled without findings', findings[0].Description)
            self.assertEqual('us-east-1', findings[0].Region)
        with self.subTest(i=3):
            self.assertEqual("prowler-aws-account_maintain_current_contact_details-999999999999-us-east-1-999999999999", findings[0].FindingUniqueId)
            self.assertEqual('Maintain current contact details.', findings[0].Description)
            self.assertEqual('us-east-1', findings[0].Region)
