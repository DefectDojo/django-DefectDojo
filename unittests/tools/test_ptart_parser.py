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
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Broken Access Control", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual("Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification or destruction of all data, or performing a business function outside of the limits of the user.", finding.description)
                self.assertEqual("Access control vulnerabilities can generally be prevented by taking a defense-in-depth approach and applying the following principles:\n\n* Never rely on obfuscation alone for access control.\n* Unless a resource is intended to be publicly accessible, deny access by default.\n* Wherever possible, use a single application-wide mechanism for enforcing access controls.\n* At the code level, make it mandatory for developers to declare the access that is allowed for each resource, and deny access by default.\n* Thoroughly audit and test access controls to ensure they are working as designed.", finding.mitigation)
                self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", finding.cvssv3)
                self.assertEqual("PTART-2024-00002", finding.unique_id_from_tool)
                self.assertEqual("Low", finding.effort_for_fixing)
                self.assertEqual("Test Assessment", finding.component_name)
                self.assertEqual("2024-09-06", finding.date.strftime("%Y-%m-%d"))
                self.assertEqual(1345, finding.cwe)
                self.assertEqual(2, len(finding.unsaved_tags))
                self.assertEqual([
                    "A01:2021-Broken Access Control",
                    "A04:2021-Insecure Design"
                ], finding.unsaved_tags)
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual(str(endpoint), "https://test.example.com")


    def test_ptart_parser_with_one_assessment_has_many_findings(self):
        with open("unittests/scans/ptart/ptart_many_vul.json") as testfile:
            parser = PTARTParser()
            findings = parser.get_findings(testfile, self.test)
            self.assertEqual(2, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Broken Access Control", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual("Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification or destruction of all data, or performing a business function outside of the limits of the user.", finding.description)
                self.assertEqual("Access control vulnerabilities can generally be prevented by taking a defense-in-depth approach and applying the following principles:\n\n* Never rely on obfuscation alone for access control.\n* Unless a resource is intended to be publicly accessible, deny access by default.\n* Wherever possible, use a single application-wide mechanism for enforcing access controls.\n* At the code level, make it mandatory for developers to declare the access that is allowed for each resource, and deny access by default.\n* Thoroughly audit and test access controls to ensure they are working as designed.", finding.mitigation)
                self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", finding.cvssv3)
                self.assertEqual("PTART-2024-00002", finding.unique_id_from_tool)
                self.assertEqual("Low", finding.effort_for_fixing)
                self.assertEqual("Test Assessment", finding.component_name)
                self.assertEqual("2024-09-06", finding.date.strftime("%Y-%m-%d"))
                self.assertEqual(1345, finding.cwe)
            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("Unrated Hit", finding.title)
                self.assertEqual("Info", finding.severity)
                self.assertEqual("Some hits are not rated.", finding.description)
                self.assertEqual("They can be informational or not related to a direct attack", finding.mitigation)
                self.assertEqual("", finding.cvssv3)
                self.assertEqual("PTART-2024-00003", finding.unique_id_from_tool)
                self.assertEqual("Low", finding.effort_for_fixing)
                self.assertEqual("Test Assessment", finding.component_name)
                self.assertEqual("2024-09-06", finding.date.strftime("%Y-%m-%d"))
                self.assertEqual(1355, finding.cwe)

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
