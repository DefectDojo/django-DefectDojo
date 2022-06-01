from ..dojo_test_case import DojoTestCase, get_unit_tests_path
from dojo.tools.whitesource.parser import WhitesourceParser
from dojo.models import Test


class TestWhitesourceParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/whitesource_sample/okhttp_no_vuln.json")
        parser = WhitesourceParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        testfile = open("unittests/scans/whitesource_sample/okhttp_one_vuln.json")
        parser = WhitesourceParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        finding = list(findings)[0]
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("WS-2009-0001", finding.unsaved_vulnerability_ids[0])

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        testfile = open("unittests/scans/whitesource_sample/okhttp_many_vuln.json")
        parser = WhitesourceParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(6, len(findings))

    def test_parse_file_with_multiple_vuln_cli_output(self):
        testfile = open(
            get_unit_tests_path() + "/scans/whitesource_sample/cli_generated_many_vulns.json"
        )
        parser = WhitesourceParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(20, len(findings))
