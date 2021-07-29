from django.test import TestCase
from dojo.tools.aws_prowler.parser import AWSProwlerParser
from django.utils import timezone
from dojo.models import Test, Engagement, Product, Product_Type, Test_Type


class TestAwsProwlerParser(TestCase):
    def setup(self, testfile):
        product_type = Product_Type(critical_product=True, key_product=False)
        product_type.save()

        test_type = Test_Type(static_tool=True, dynamic_tool=False)
        test_type.save()

        product = Product(prod_type=product_type)
        product.save()

        engagement = Engagement(
            product=product, target_start=timezone.now(), target_end=timezone.now()
        )
        engagement.save()

        parser = AWSProwlerParser()
        findings = parser.get_findings(
            testfile,
            Test(
                engagement=engagement,
                test_type=test_type,
                target_start=timezone.now(),
                target_end=timezone.now(),
            ),
        )

        testfile.close()

        return findings

    def test_aws_prowler_parser_with_no_vuln_has_no_findings(self):
        findings = self.setup(
            open("dojo/unittests/scans/aws_prowler/no_vuln.csv"))
        self.assertEqual(0, len(findings))

    def test_aws_prowler_parser_with_critical_vuln_has_one_findings(self):
        findings = self.setup(
            open("dojo/unittests/scans/aws_prowler/one_vuln.csv"))
        self.assertEqual(1, len(findings))
        self.assertEqual(
            "Root user in the account wasn't accessed in the last 1 days", findings[0].title
        )

    def test_aws_prowler_parser_with_many_vuln_has_many_findings(self):
        findings = self.setup(
            open("dojo/unittests/scans/aws_prowler/many_vuln.csv"))
        self.assertEqual(4, len(findings))
        self.assertEqual(
            "Root user in the account wasn't accessed in the last 1 days", findings[0].title)
        self.assertEqual("Critical", findings[0].severity)
        self.assertEqual(
            "User example_user has never used access key 1 since creation and not rotated it in the past 90 days", findings[1].title)
        self.assertEqual("Critical", findings[1].severity)
        self.assertEqual("Password Policy has weak reuse requirement (lower than 24)", findings[2].title)
        self.assertEqual("Critical", findings[2].severity)
        self.assertEqual("eu-west-2: sg-01234567890qwerty is not being used!", findings[3].title)
        self.assertEqual("High", findings[3].severity)

    def test_aws_prowler_parser_with_many_vuln_has_many_findings2(self):
        findings = self.setup(
            open("dojo/unittests/scans/aws_prowler/many_vuln2.csv"))
        self.assertEqual(175, len(findings))
        self.assertEqual("Root user in the account wasn't accessed in the last 1 days", findings[0].title)
        self.assertEqual("Info", findings[0].severity)
        self.assertEqual(
            "User example has never used access key 1 since creation and not rotated it in the past 90 days", findings[4].title)
        self.assertEqual("Critical", findings[6].severity)

    def test_aws_prowler_parser_issue4450(self):
        findings = self.setup(
            open("dojo/unittests/scans/aws_prowler/issue4450.csv"))
        self.assertEqual(4, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertFalse(finding.active)
            self.assertEqual(
                "Root user in the account wasn't accessed in the last 1 days", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertEqual(1032, finding.cwe)
        with self.subTest(i=1):
            finding = findings[1]
            self.assertTrue(finding.active)
            self.assertEqual(
                "User ansible-test-user has Password enabled but MFA disabled", finding.title)
            self.assertEqual("Critical", finding.severity)
            self.assertEqual(1032, finding.cwe)
            self.assertEqual(1, finding.nb_occurences)
