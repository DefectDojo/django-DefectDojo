from dojo.models import Test
from dojo.tools.immuniweb.parser import ImmuniwebParser
from unittests.dojo_test_case import DojoTestCase


class TestImmuniwebParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        with open("unittests/scans/immuniweb/ImmuniWeb-0-vuln.xml") as testfile:
            parser = ImmuniwebParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        with open("unittests/scans/immuniweb/ImmuniWeb-1-vuln.xml") as testfile:
            parser = ImmuniwebParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        with open("unittests/scans/immuniweb/ImmuniWeb-multiple-vuln.xml") as testfile:
            parser = ImmuniwebParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertGreater(len(findings), 2)
