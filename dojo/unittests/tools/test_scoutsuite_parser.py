from django.test import TestCase
from dojo.tools.scout_suite.parser import ScoutSuiteParser
from django.utils import timezone
from dojo.models import Test, Engagement, Product, Product_Type, Test_Type


class MockFileObject:
    def __init__(self, filepath):
        self.filepath = filepath

    def temporary_file_path(self):
        return self.filepath


class TestScoutSuiteParser(TestCase):
    def setup(self, testfile):
        file = MockFileObject(testfile)
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

        parser = ScoutSuiteParser()
        return parser.get_findings(
            file,
            Test(
                engagement=engagement,
                test_type=test_type,
                target_start=timezone.now(),
                target_end=timezone.now(),
            ),
        )

    def test_scout_suite_parser_with_no_vuln_has_no_findings(self):
        findings = self.setup("dojo/unittests/scans/scout_suite/no_vuln.js")
        self.assertEqual(0, len(findings))

    def test_scout_suite_parser_with_two_findings(self):
        findings = self.setup("dojo/unittests/scans/scout_suite/two_findings.js")
        self.assertEqual(2, len(findings))
