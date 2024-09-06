from pprint import pprint

from django.test import TestCase

from dojo.models import Test, Product, Engagement
from dojo.tools.ptart.parser import PTARTParser


class TestPTARTParser(TestCase):

    def setUp(self):
        self.product = Product(name="sample product",
                               description="what a description")
        self.engagement = Engagement(name="sample engagement",
                                     product=self.product)
        self.test = Test(engagement=self.engagement)

    def test_ptart_parser_with_no_assessments_has_no_findings(self):
        with open("unittests/scans/ptart/ptart_zero_vul.json") as testfile:
            parser = PTARTParser()
            findings = parser.get_findings(testfile, self.test)
            self.assertEqual(0, len(findings))
            self.assertEqual([], findings)

    def test_ptart_parser_with_one_assessment_has_one_finding(self):
        with open("unittests/scans/ptart/ptart_one_vul.json") as testfile:
            parser = PTARTParser()
            findings = parser.get_findings(testfile, self.test)
            self.assertEqual(1, len(findings))
            self.assertEqual("Broken Access Control", findings[0].title)
    #
    #
    # def test_ptart_parser_with_no_vuln_has_no_findings(self):
    #     testfile = open("unittests/scans/ptart/ptart_zero_vul.json")
    #     parser = PTARTParser()
    #     findings = parser.get_findings(testfile, self.test)
    #     testfile.close()
    #     self.assertEqual(0, len(findings))
    #
    # def test_ptart_parser_with_one_criticle_vuln_has_one_findings(self):
    #     testfile = open("unittests/scans/ptart/ptart_one_vul.json")
    #     parser = PTARTParser()
    #     findings = parser.get_findings(testfile, Test())
    #     testfile.close()
    #     for finding in findings:
    #         for endpoint in finding.unsaved_endpoints:
    #             endpoint.clean()
    #     self.assertEqual(1, len(findings))
    #     self.assertEqual("handlebars", findings[0].component_name)
    #     self.assertEqual("4.5.2", findings[0].component_version)
    #
    # def test_ptart_parser_with_many_vuln_has_many_findings(self):
    #     testfile = open("unittests/scans/ptart/ptart_many_vul.json")
    #     parser = PTARTParser()
    #     findings = parser.get_findings(testfile, Test())
    #     testfile.close()
    #     for finding in findings:
    #         for endpoint in finding.unsaved_endpoints:
    #             endpoint.clean()
    #     self.assertEqual(3, len(findings))
    #
    # def test_ptart_parser_empty_with_error(self):
    #     with self.assertRaises(ValueError) as context:
    #         testfile = open("unittests/scans/ptart/empty_with_error.json")
    #         parser = PTARTParser()
    #         findings = parser.get_findings(testfile, Test())
    #         testfile.close()
    #         for finding in findings:
    #             for endpoint in finding.unsaved_endpoints:
    #                 endpoint.clean()
    #         self.assertTrue(
    #             "PTART report contains errors:" in str(context.exception)
    #         )
    #         self.assertTrue("ECONNREFUSED" in str(context.exception))
