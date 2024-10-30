from dojo.models import Test
from dojo.tools.kiuwan.parser import KiuwanParser
from unittests.dojo_test_case import DojoTestCase


class TestKiuwanParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        with open("unittests/scans/kiuwan/kiuwan_no_vuln.csv", encoding="utf-8") as testfile:
            parser = KiuwanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_two_vuln_has_two_findings(self):
        with open("unittests/scans/kiuwan/kiuwan_two_vuln.csv", encoding="utf-8") as testfile:
            parser = KiuwanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        with open("unittests/scans/kiuwan/kiuwan_many_vuln.csv", encoding="utf-8") as testfile:
            parser = KiuwanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(131, len(findings))

    def test_parse_file_with_defects(self):
        with open("unittests/scans/kiuwan/kiuwan_defects.csv", encoding="utf-8") as testfile:
            parser = KiuwanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_file_issue_9308(self):
        with open("unittests/scans/kiuwan/issue_9308.csv", encoding="utf-8") as testfile:
            parser = KiuwanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
