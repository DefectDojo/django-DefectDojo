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
        findings = self.setup(open("dojo/unittests/scans/aws_prowler/no_vuln.csv"))
        self.assertEqual(0, len(findings))

    def test_aws_prowler_parser_with_critical_vuln_has_one_findings(self):
        findings = self.setup(open("dojo/unittests/scans/aws_prowler/one_vuln.csv"))
        self.assertEqual(1, len(findings))
        self.assertEqual(
            "Avoid the use of the root account (Scored)", findings[0].title
        )

    def test_aws_prowler_parser_with_many_vuln_has_many_findings(self):
        findings = self.setup(open("dojo/unittests/scans/aws_prowler/many_vuln.csv"))
        self.assertEqual(5, len(findings))
        self.assertEqual("Vuln A", findings[0].title)
        self.assertEqual("Critical", findings[0].severity)
        self.assertEqual("Vuln B", findings[1].title)
        self.assertEqual("Critical", findings[1].severity)
        self.assertEqual("Info A", findings[2].title)
        self.assertEqual("Info", findings[2].severity)
        self.assertEqual("Vuln C", findings[3].title)
        self.assertEqual("High", findings[3].severity)
        self.assertEqual("Info B", findings[4].title)
        self.assertEqual("Info", findings[4].severity)

    def test_aws_prowler_parser_with_many_vuln_has_many_findings2(self):
        findings = self.setup(open("dojo/unittests/scans/aws_prowler/many_vuln2.csv"))
        self.assertEqual(183, len(findings))
        self.assertEqual("Show report generation info", findings[0].title)
        self.assertEqual("Info", findings[0].severity)
        self.assertEqual(1032, findings[0].cwe)
