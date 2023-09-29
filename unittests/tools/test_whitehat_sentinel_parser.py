from ..dojo_test_case import DojoTestCase

from dojo.models import Test
from dojo.tools.whitehat_sentinel.parser import WhiteHatSentinelParser


class TestWhiteHatSentinelParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        with self.assertRaises(ValueError):
            testfile = open("unittests/scans/whitehat_sentinel/empty_file.json")
            parser = WhiteHatSentinelParser()
            parser.get_findings(testfile, Test())

    def test_parse_file_with_one_vuln_has_one_findings(self):
        testfile = open("unittests/scans/whitehat_sentinel/one_vuln.json")
        parser = WhiteHatSentinelParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        testfile = open("unittests/scans/whitehat_sentinel/many_vuln.json")
        parser = WhiteHatSentinelParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(3, len(findings))

    def test_parse_file_with_invalid_data(self):
        with self.assertRaises(ValueError):
            testfile = open("unittests/scans/whitehat_sentinel/invalid_data.txt")
            parser = WhiteHatSentinelParser()
            parser.get_findings(testfile, Test())
