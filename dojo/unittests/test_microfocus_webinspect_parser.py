from django.test import TestCase
from dojo.tools.microfocus_webinspect.parser import MicrofocusWebinspectXMLParser
from dojo.models import Test


class TestMicrofocusWebinspectXMLParser(TestCase):

    def test_parse_without_file_has_no_findings(self):
        parser = MicrofocusWebinspectXMLParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_no_vuln_has_no_findings(self):

        testfile = open("dojo/unittests/scans/microfocus_webinspect/Webinspect_no_vuln.xml")
        parser = MicrofocusWebinspectXMLParser(testfile, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        testfile = open("dojo/unittests/scans/microfocus_webinspect/Webinspect_one_vuln.xml")
        parser = MicrofocusWebinspectXMLParser(testfile, Test())
        self.assertEqual(1, len(parser.items))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        testfile = open("dojo/unittests/scans/microfocus_webinspect/Webinspect_many_vuln.xml")
        parser = MicrofocusWebinspectXMLParser(testfile, Test())
        self.assertEqual(8, len(parser.items))
