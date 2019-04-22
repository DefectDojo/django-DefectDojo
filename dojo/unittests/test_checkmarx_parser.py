from django.test import TestCase

from dojo.models import Test, Engagement, Product
from dojo.tools.checkmarx.parser import CheckmarxXMLParser


class TestCheckmarxParser(TestCase):

    def test_parse_file_with_no_vulnerabilities_has_no_findings(self):
        my_file_handle = open("dojo/unittests/scans/checkmarx/no_finding.xml")
        product = Product()
        engagement = Engagement()
        test = Test()
        engagement.product = product
        test.engagement = engagement
        self.parser = CheckmarxXMLParser(my_file_handle, test)
        my_file_handle.close()
        self.assertEqual(0, len(self.parser.items))

    def test_parse_file_with_single_vulnerability_has_single_finding(self):
        my_file_handle = open("dojo/unittests/scans/checkmarx/single_finding.xml")
        product = Product()
        engagement = Engagement()
        test = Test()
        engagement.product = product
        test.engagement = engagement
        self.parser = CheckmarxXMLParser(my_file_handle, test)
        my_file_handle.close()
        self.assertEqual(1, len(self.parser.items))

    def test_parse_file_with_multiple_vulnerabilities_has_multiple_findings(self):
        my_file_handle = open("dojo/unittests/scans/checkmarx/multiple_findings.xml")
        product = Product()
        engagement = Engagement()
        test = Test()
        engagement.product = product
        test.engagement = engagement
        self.parser = CheckmarxXMLParser(my_file_handle, test)
        my_file_handle.close()
        # checkmarx says 3 but we're down to 2 due to the aggregation on sink filename rather than source filename + source line number + sink filename + sink line number
        self.assertEqual(2, len(self.parser.items))

    def test_parse_file_with_utf8_replacement_char(self):
        my_file_handle = open("dojo/unittests/scans/checkmarx/utf8_replacement_char.xml")
        product = Product()
        engagement = Engagement()
        test = Test()
        engagement.product = product
        test.engagement = engagement
        self.parser = CheckmarxXMLParser(my_file_handle, test)
        my_file_handle.close()
        self.assertEqual(1, len(self.parser.items))

    def test_parse_file_with_utf8_various_non_ascii_char(self):
        my_file_handle = open("dojo/unittests/scans/checkmarx/utf8_various_non_ascii_char.xml")
        product = Product()
        engagement = Engagement()
        test = Test()
        engagement.product = product
        test.engagement = engagement
        self.parser = CheckmarxXMLParser(my_file_handle, test)
        my_file_handle.close()
        self.assertEqual(1, len(self.parser.items))
