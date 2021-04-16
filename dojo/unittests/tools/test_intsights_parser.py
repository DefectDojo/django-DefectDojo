from django.test import TestCase
from dojo.tools.intsights.parser import IntSightsParser
from dojo.models import Engagement, Product, Test


class TestIntSightsParser(TestCase):
    def get_test(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        return test

    def test_intsights_parser_without_file_has_no_findings(self):
        parser = IntSightsParser()
        findings = parser.get_findings(None, self.get_test())
        self.assertEqual(0, len(findings))

    def test_intsights_parser_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/intsights/intsights_zero_vul.json")
        parser = IntSightsParser()
        findings = parser.get_findings(testfile, self.get_test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_intsights_parser_with_one_criticle_vuln_has_one_findings(self):
        testfile = open("dojo/unittests/scans/intsights/intsights_one_vul.json")
        parser = IntSightsParser()
        findings = parser.get_findings(testfile, self.get_test())
        testfile.close()
        self.assertEqual(1, len(findings))
        self.assertEqual("handlebars", findings[0].component_name)
        self.assertEqual("4.5.2", findings[0].component_version)

    def test_intsights_parser_with_many_vuln_has_many_findings(self):
        testfile = open("dojo/unittests/scans/intsights/intsights_many_vul.json")
        parser = IntSightsParser()
        findings = parser.get_findings(testfile, self.get_test())
        testfile.close()
        self.assertEqual(3, len(findings))

    def test_intsights_parser_empty_with_error(self):
        with self.assertRaises(ValueError) as context:
            testfile = open("dojo/unittests/scans/intsights/empty_with_error.json")
            parser = IntSightsParser()
            findings = parser.get_findings(testfile, self.get_test())
            testfile.close()
            self.assertTrue(
                "IntSights report contains errors:" in str(context.exception)
            )
            self.assertTrue("ECONNREFUSED" in str(context.exception))
