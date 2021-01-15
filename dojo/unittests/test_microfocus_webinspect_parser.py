from django.test import TestCase
from dojo.tools.microfocus_webinspect.parser import MicrofocusWebinspectXMLParser
from dojo.models import Test, Engagement, Product


class TestMicrofocusWebinspectXMLParser(TestCase):

    def test_parse_without_file_has_no_findings(self):
        parser = MicrofocusWebinspectXMLParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_no_vuln_has_no_findings(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        testfile = open("dojo/unittests/scans/microfocus_webinspect/Webinspect_no_vuln.xml")
        parser = MicrofocusWebinspectXMLParser(testfile, test)
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        testfile = open("dojo/unittests/scans/microfocus_webinspect/Webinspect_one_vuln.xml")
        parser = MicrofocusWebinspectXMLParser(testfile, test)
        self.assertEqual(1, len(parser.items))
        item = parser.items[0]
        self.assertEqual(200, item.cwe)
        self.assertLess(0, len(item.unsaved_endpoints))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        testfile = open("dojo/unittests/scans/microfocus_webinspect/Webinspect_many_vuln.xml")
        parser = MicrofocusWebinspectXMLParser(testfile, test)
        self.assertEqual(8, len(parser.items))
        item = parser.items[1]
        self.assertEqual(525, item.cwe)
        self.assertIsNotNone(item.references)
        self.assertEqual("1cfe38ee-89f7-4110-ad7c-8fca476b2f04", item.unique_id_from_tool)
        self.assertLess(0, len(item.unsaved_endpoints))

    def test_convert_severity(self):
        with self.subTest("convert info", val="0"):
            self.assertEqual("Info", MicrofocusWebinspectXMLParser.convert_severity("0"))
        with self.subTest("convert medium", val="2"):
            self.assertEqual("Medium", MicrofocusWebinspectXMLParser.convert_severity("2"))
