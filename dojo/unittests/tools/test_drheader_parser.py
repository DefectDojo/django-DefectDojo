from django.test import TestCase
from dojo.tools.drheader.parser import DrHeaderParser
from dojo.models import Test


class TestDrHeaderParser(TestCase):

    def test_parse_file_has_many_finding_one_tool(self):
        testfile = open("dojo/unittests/scans/drheader/scan.json")
        parser = DrHeaderParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(6, len(findings))

    def test_parse_file_has_many_finding_one_tool2(self):
        testfile = open("dojo/unittests/scans/drheader/scan2.json")
        parser = DrHeaderParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(6, len(findings))

    def test_parse_file_has_many_finding_one_tool3(self):
        testfile = open("dojo/unittests/scans/drheader/scan3.json")
        parser = DrHeaderParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(11, len(findings))
