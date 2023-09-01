from ..dojo_test_case import DojoTestCase
from dojo.tools.drheader.parser import DrHeaderParser
from dojo.models import Test


class TestDrHeaderParser(DojoTestCase):

    def test_parse_file_has_no_findings(self):
        testfile = open("unittests/scans/drheader/no_vulns.json")
        parser = DrHeaderParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parse_file_has_many_finding_one_tool(self):
        testfile = open("unittests/scans/drheader/scan.json")
        parser = DrHeaderParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(6, len(findings))

    def test_parse_file_has_many_finding_one_tool2(self):
        testfile = open("unittests/scans/drheader/scan2.json")
        parser = DrHeaderParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(6, len(findings))

    def test_parse_file_has_many_finding_one_tool3(self):
        testfile = open("unittests/scans/drheader/scan3.json")
        parser = DrHeaderParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(11, len(findings))

    def test_parse_file_has_many_finding_multiple_urls(self):
        testfile = open("unittests/scans/drheader/multiple_urls.json")
        parser = DrHeaderParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        testfile.close()
        self.assertEqual(4, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual(443, endpoint.port)
            self.assertEqual("example.com", endpoint.host)
