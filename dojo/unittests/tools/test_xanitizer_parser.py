from django.test import TestCase
from dojo.tools.xanitizer.parser import XanitizerParser
from dojo.models import Test


class TestXanitizerParser(TestCase):

    def test_parse_file_with_no_findings(self):
        testfile = open("dojo/unittests/scans/xanitizer/no-findings.xml")
        parser = XanitizerParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_findings(self):
        testfile = open("dojo/unittests/scans/xanitizer/one-findings.xml")
        parser = XanitizerParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_findings(self):
        testfile = open("dojo/unittests/scans/xanitizer/multiple-findings.xml")
        parser = XanitizerParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(9, len(findings))

    def test_parse_file_with_multiple_findings_no_details(self):
        testfile = open(
            "dojo/unittests/scans/xanitizer/multiple-findings-no-details.xml"
        )
        parser = XanitizerParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(9, len(findings))
