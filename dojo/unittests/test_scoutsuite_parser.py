from django.test import TestCase
from dojo.tools.scout_suite.parser import ScoutSuiteParser
from django.utils import timezone
from dojo.models import Test, Engagement, Product, Product_Type, Test_Type


class TestScoutSuiteParser(TestCase):

    def setup(self, testfile):
        product_type = Product_Type(critical_product=True, key_product=False)
        product_type.save()

        test_type = Test_Type(static_tool=True, dynamic_tool=False)
        test_type.save()

        product = Product(prod_type=product_type)
        product.save()

        engagement = Engagement(product=product, target_start=timezone.now(), target_end=timezone.now())
        engagement.save()

        parser = ScoutSuiteParser(testfile, Test(engagement=engagement, test_type=test_type, target_start=timezone.now(), target_end=timezone.now()))

        testfile.close()

        return parser

    def test_scout_suite_parser_with_no_vuln_has_no_findings(self):
        parser = self.setup(open("dojo/unittests/scans/scout_suite/no_vuln.csv"))
        self.assertEqual(0, len(parser.items))

    def test_scout_suite_parser_with_critical_vuln_has_one_findings(self):
        parser = self.setup(open("dojo/unittests/scans/scout_suite/one_vuln.csv"))
        self.assertEqual(1, len(parser.items))
        self.assertEqual('Avoid the use of the root account (Scored)', parser.items[0].title)

    def test_scout_suite_parser_with_many_vuln_has_many_findings(self):
        parser = self.setup(open("dojo/unittests/scans/scout_suite/many_vuln.csv"))
        self.assertEqual(5, len(parser.items))
        self.assertEqual('Vuln A', parser.items[0].title)
        self.assertEqual('Vuln B', parser.items[1].title)
        self.assertEqual('Info A', parser.items[2].title)
        self.assertEqual('Vuln C', parser.items[3].title)
        self.assertEqual('Info B', parser.items[4].title)
