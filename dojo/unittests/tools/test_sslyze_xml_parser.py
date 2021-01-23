from django.test import TestCase
from dojo.tools.sslyze.parser_xml import SSLyzeXMLParser
from dojo.models import Test


class TestSSLyzeXMLParser(TestCase):

    def test_parse_without_file_has_no_findings(self):
        parser = SSLyzeXMLParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_one_target_has_one_vuln(self):
        testfile = open("dojo/unittests/scans/sslyze/report_one_target_one_vuln.xml")
        parser = SSLyzeXMLParser(testfile, Test())
        self.assertEqual(1, len(parser.items))

    def test_parse_file_with_one_target_has_three_vuln(self):
        testfile = open("dojo/unittests/scans/sslyze/report_one_target_three_vuln.xml")
        parser = SSLyzeXMLParser(testfile, Test())
        self.assertEqual(3, len(parser.items))

    def test_parse_file_with_two_target_has_many_vuln(self):
        testfile = open("dojo/unittests/scans/sslyze/report_two_target_many_vuln.xml")
        parser = SSLyzeXMLParser(testfile, Test())
        self.assertEqual(7, len(parser.items))
