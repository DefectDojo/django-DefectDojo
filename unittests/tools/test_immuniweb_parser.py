from ..dojo_test_case import DojoTestCase
from dojo.tools.immuniweb.parser import ImmuniwebParser
from dojo.models import Test


class TestImmuniwebParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/immuniweb/ImmuniWeb-0-vuln.xml")
        parser = ImmuniwebParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        testfile = open("unittests/scans/immuniweb/ImmuniWeb-1-vuln.xml")
        parser = ImmuniwebParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        testfile = open("unittests/scans/immuniweb/ImmuniWeb-multiple-vuln.xml")
        parser = ImmuniwebParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertTrue(len(findings) > 2)
