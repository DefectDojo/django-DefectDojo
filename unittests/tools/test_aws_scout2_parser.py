from ..dojo_test_case import DojoTestCase
from dojo.tools.aws_scout2.parser import AWSScout2Parser
from django.utils import timezone
from dojo.models import Test, Engagement, Product, Product_Type, Test_Type


class TestAwsProwlerParser(DojoTestCase):
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

        parser = AWSScout2Parser()
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

    def test_parser_with_critical_vuln_has_one_findings(self):
        findings = self.setup(open("unittests/scans/aws_scout2/aws_config.js"))
        self.assertEqual(21, len(findings))
        self.assertEqual("Global services logging disabled", findings[0].title)
        self.assertEqual("Critical", findings[0].severity)
        self.assertEqual(1032, findings[0].cwe)
        self.assertEqual("Unused security groups", findings[6].title)
        self.assertEqual("Medium", findings[6].severity)
        self.assertEqual(1032, findings[6].cwe)
