from ..dojo_test_case import DojoParserTestCase
from dojo.tools.bugcrowd.parser import BugCrowdParser
from dojo.models import Test
from datetime import datetime, timezone


class TestBugCrowdParser(DojoParserTestCase):

    parser = BugCrowdParser()

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/bugcrowd/BugCrowd-zero.csv")
        findings = self.parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        testfile = open("unittests/scans/bugcrowd/BugCrowd-one.csv")
        findings = self.parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))
        self.assertEqual(findings[0].date, datetime(2020, 3, 1, 6, 15, 6, tzinfo=timezone.utc))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        testfile = open("unittests/scans/bugcrowd/BugCrowd-many.csv")
        findings = self.parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(5, len(findings))
