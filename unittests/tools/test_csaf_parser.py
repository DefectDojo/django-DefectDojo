from ..dojo_test_case import DojoTestCase
from dojo.models import Test
from dojo.tools.csaf.parser import CsafParser
# from jsonschema import ValidationError


class TestCsafParser(DojoTestCase):
    def test_parse_file_has_one_finding(self):
        testfile = open("unittests/scans/csaf/csaf_one_vuln.json")
        parser = CsafParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))

    def test_parse_file_has_two_findings(self):
        testfile = open("unittests/scans/csaf/csaf_two_vulns.json")
        parser = CsafParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(2, len(findings))

    def test_parse_file_doesnt_have_publisher(self):
        testfile = open("unittests/scans/csaf/csaf_without_publisher.json")
        parser = CsafParser()
        self.assertRaises(Exception, parser.get_findings, testfile, Test())
        testfile.close()

    def test_parse_file_no_vulnerabilities(self):
        testfile = open("unittests/scans/csaf/csaf_without_vulns.json")
        parser = CsafParser()
        self.assertRaises(Exception, parser.get_findings, testfile, Test())
        testfile.close()
