from django.test import TestCase
from dojo.tools.sslyze.parser_xml import SSLyzeXMLParser
from dojo.tools.sslyze.parser import SslyzeParser
from dojo.models import Test


class TestSSLyzeXMLParser(TestCase):

    def test_parse_file_with_one_target_has_three_vuln(self):
        testfile = open("dojo/unittests/scans/sslyze/report_one_target_three_vuln.xml")
        parser = SslyzeParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(3, len(findings))

    def test_parse_xml_file_with_one_target_has_one_vuln(self):
        testfile = open("dojo/unittests/scans/sslyze/report_one_target_one_vuln.xml")
        parser = SSLyzeXMLParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))

    def test_parse_xml_file_with_one_target_has_three_vuln(self):
        testfile = open("dojo/unittests/scans/sslyze/report_one_target_three_vuln.xml")
        parser = SSLyzeXMLParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(3, len(findings))

    def test_parse_xml_file_with_two_target_has_many_vuln(self):
        testfile = open("dojo/unittests/scans/sslyze/report_two_target_many_vuln.xml")
        parser = SSLyzeXMLParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(7, len(findings))
