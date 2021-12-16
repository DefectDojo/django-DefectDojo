from ..dojo_test_case import DojoTestCase
from dojo.tools.rusty_hog.parser import RustyhogParser
from dojo.models import Test


class TestRustyhogParser(DojoTestCase):
    def test_parse_file_with_no_vuln_has_no_finding_choctawhog(self):
        testfile = open("unittests/scans/rusty_hog/choctawhog_no_vuln.json")
        parser = RustyhogParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding_choctawhog(self):
        testfile = open("unittests/scans/rusty_hog/choctawhog_one_vuln.json")
        parser = RustyhogParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding_choctawhog(self):
        testfile = open("unittests/scans/rusty_hog/choctawhog_many_vulns.json")
        parser = RustyhogParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(13, len(findings))

    def test_parse_file_with_no_vuln_has_no_finding_gottingenhog(self):
        testfile = open("unittests/scans/rusty_hog/gottingenhog_no_vuln.json")
        parser = RustyhogParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding_gottingenhog(self):
        testfile = open("unittests/scans/rusty_hog/gottingenhog_one_vuln.json")
        parser = RustyhogParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding_gottingenhog(self):
        testfile = open("unittests/scans/rusty_hog/gottingenhog_many_vulns.json")
        parser = RustyhogParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(10, len(findings))
