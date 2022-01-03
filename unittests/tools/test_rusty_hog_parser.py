from ..dojo_test_case import DojoTestCase
from dojo.tools.rusty_hog.parser import RustyhogParser
from dojo.models import Test


class TestRustyhogParser(DojoTestCase):
    def test_parse_file_with_no_vuln_has_no_finding_choctawhog(self):
        testfile = open("unittests/scans/rusty_hog/choctawhog_no_vuln.json")
        parser = RustyhogParser()
        findings = parser.get_items(testfile, "Rusty Hog", Test())  # The outputfile is empty. A subscanner can't be classified
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding_choctawhog(self):
        testfile = open("unittests/scans/rusty_hog/choctawhog_one_vuln.json")
        parser = RustyhogParser()
        findings = parser.get_items(testfile, "Choctaw Hog", Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding_choctawhog(self):
        testfile = open("unittests/scans/rusty_hog/choctawhog_many_vulns.json")
        parser = RustyhogParser()
        findings = parser.get_items(testfile, "Choctaw Hog", Test())
        self.assertEqual(13, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding_choctawhog_content(self):
        testfile = open("unittests/scans/rusty_hog/choctawhog_many_vulns.json")
        parser = RustyhogParser()
        findings = parser.get_items(testfile, "Choctaw Hog", Test())
        self.assertEqual(findings[0].title, "Email address found in Git path .github/workflows/main.yml (a7bce96377c4ff2ac16cd51fb0da7fe7ea678829)")
        self.assertIn("**This string was found:** ['dojo-helpers@this-repo.com']", findings[0].description)
        self.assertIn("**Commit message:** removing action", findings[0].description)
        self.assertIn("**Commit hash:** a7bce96377c4ff2ac16cd51fb0da7fe7ea678829", findings[0].description)
        self.assertIn("**Parent commit hash:** d8b2f39e826321896a3c7c474fc40dfc0d1fc586", findings[0].description)
        self.assertIn("**Old and new file IDs:** 2aba123d6e872777c8cf39ee34664d70e0b90ff0 - 0000000000000000000000000000000000000000", findings[0].description)
        self.assertIn("**Date:** 2020-04-15 12:47:20", findings[0].description)

    def test_parse_file_with_no_vuln_has_no_finding_gottingenhog(self):
        testfile = open("unittests/scans/rusty_hog/gottingenhog_no_vuln.json")
        parser = RustyhogParser()
        findings = parser.get_items(testfile, "Rusty Hog", Test())  # The outputfile is empty. A subscanner can't be classified
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding_gottingenhog(self):
        testfile = open("unittests/scans/rusty_hog/gottingenhog_one_vuln.json")
        parser = RustyhogParser()
        findings = parser.get_items(testfile, "Gottingen Hog", Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding_gottingenhog(self):
        testfile = open("unittests/scans/rusty_hog/gottingenhog_many_vulns.json")
        parser = RustyhogParser()
        findings = parser.get_items(testfile, "Gottingen Hog", Test())
        self.assertEqual(10, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding_gottingenhog_content(self):
        testfile = open("unittests/scans/rusty_hog/gottingenhog_many_vulns.json")
        parser = RustyhogParser()
        findings = parser.get_items(testfile, "Gottingen Hog", Test())
        self.assertEqual(findings[0].title, "password found in Jira ID TEST-123 (Issue Description)")
        self.assertIn("**This string was found:** ['password: jeans']", findings[0].description)
        self.assertIn("**JIRA Issue ID:** TEST-123", findings[0].description)
        self.assertIn("**JIRA location:** Issue Description", findings[0].description)
        self.assertIn("**JIRA url:** https://jira.com/browse/TEST-123", findings[0].description)
