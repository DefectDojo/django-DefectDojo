from os import path

from django.test import TestCase
from dojo.models import Test
from dojo.tools.sslyze.parser import SslyzeParser
from dojo.tools.sslyze.parser_json import SSLyzeJSONParser
from dojo.tools.sslyze.parser_xml import SSLyzeXMLParser


class TestSslyzeJSONParser(TestCase):

    def test_parse_file_with_one_target_has_one_vuln(self):
        testfile = open(path.join(path.dirname(__file__), "scans/sslyze/one_target_one_vuln.json"))
        parser = SslyzeParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_json_file_with_one_target_has_zero_vuln(self):
        testfile = open(path.join(path.dirname(__file__), "scans/sslyze/one_target_zero_vuln.json"))
        parser = SSLyzeJSONParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_json_file_with_one_target_has_one_vuln(self):
        testfile = open(path.join(path.dirname(__file__), "scans/sslyze/one_target_one_vuln.json"))
        parser = SSLyzeJSONParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_json_file_with_one_target_has_four_vuln(self):
        testfile = open(path.join(path.dirname(__file__), "scans/sslyze/one_target_many_vuln.json"))
        parser = SSLyzeJSONParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(4, len(findings))

    def test_parse_json_file_with_two_target_has_many_vuln(self):
        testfile = open(path.join(path.dirname(__file__), "scans/sslyze/two_targets_two_vuln.json"))
        parser = SSLyzeJSONParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(2, len(findings))


class TestSSLyzeXMLParser(TestCase):

    def test_parse_file_with_one_target_has_three_vuln(self):
        testfile = open(path.join(path.dirname(__file__), "scans/sslyze/report_one_target_three_vuln.xml"))
        parser = SslyzeParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(3, len(findings))

    def test_parse_xml_file_with_one_target_has_one_vuln(self):
        testfile = open(path.join(path.dirname(__file__), "scans/sslyze/report_one_target_one_vuln.xml"))
        parser = SSLyzeXMLParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_xml_file_with_one_target_has_three_vuln(self):
        testfile = open(path.join(path.dirname(__file__), "scans/sslyze/report_one_target_three_vuln.xml"))
        parser = SSLyzeXMLParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(3, len(findings))

    def test_parse_xml_file_with_two_target_has_many_vuln(self):
        testfile = open(path.join(path.dirname(__file__), "scans/sslyze/report_two_target_many_vuln.xml"))
        parser = SSLyzeXMLParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(7, len(findings))
