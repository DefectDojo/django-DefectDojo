from django.test import TestCase
from dojo.tools.huskyci.parser import HuskyCIReportParser
from dojo.models import Test


class TestHuskyCIReportParser(TestCase):

    def test_parse_without_file_has_no_finding(self):
        parser = HuskyCIReportParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_no_finding(self):
        testfile = open(
            "dojo/unittests/scans/huskyci/huskyci_report_no_finding.json")
        parser = HuskyCIReportParser(testfile, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_has_one_finding_one_tool(self):
        testfile = open(
            "dojo/unittests/scans/huskyci/huskyci_report_one_finding_one_tool.json")
        parser = HuskyCIReportParser(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(parser.items))

    def test_parse_file_has_many_finding_one_tool(self):
        testfile = open(
            "dojo/unittests/scans/huskyci/huskyci_report_many_finding_one_tool.json")
        parser = HuskyCIReportParser(testfile, Test())
        testfile.close()
        self.assertEqual(3, len(parser.items))

    def test_parse_file_has_many_finding_two_tools(self):
        testfile = open(
            "dojo/unittests/scans/huskyci/huskyci_report_many_finding_two_tools.json")
        parser = HuskyCIReportParser(testfile, Test())
        testfile.close()
        self.assertEqual(15, len(parser.items))
