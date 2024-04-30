from ..dojo_test_case import DojoTestCase, get_unit_tests_path
from dojo.tools.huskyci.parser import HuskyCIParser
from dojo.models import Test


class TestHuskyCIParser(DojoTestCase):

    def test_parse_file_no_finding(self):
        with open("unittests/scans/huskyci/huskyci_report_no_finding.json") as testfile:
            parser = HuskyCIParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_has_one_finding_one_tool(self):
        with open(
            get_unit_tests_path() + "/scans/huskyci/huskyci_report_one_finding_one_tool.json"
        ) as testfile:
            parser = HuskyCIParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_file_has_many_finding_one_tool(self):
        with open(
            get_unit_tests_path() + "/scans/huskyci/huskyci_report_many_finding_one_tool.json"
        ) as testfile:
            parser = HuskyCIParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

    def test_parse_file_has_many_finding_two_tools(self):
        with open(
            get_unit_tests_path() + "/scans/huskyci/huskyci_report_many_finding_two_tools.json"
        ) as testfile:
            parser = HuskyCIParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(15, len(findings))
