from ..dojo_test_case import DojoTestCase
from dojo.tools.wfuzz.parser import WFuzzParser
from dojo.models import Test


class TestWFuzzParser(DojoTestCase):

    def test_parse_no_findings(self):
        testfile = open("unittests/scans/wfuzz/no_findings.json")
        parser = WFuzzParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        testfile = open("unittests/scans/wfuzz/one_finding.json")
        parser = WFuzzParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))

    def test_parse_many_finding(self):
        testfile = open("unittests/scans/wfuzz/many_findings.json")
        parser = WFuzzParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(4, len(findings))

    def test_one_dup_finding(self):
        testfile = open("unittests/scans/wfuzz/one_dup_finding.json")
        parser = WFuzzParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(4, len(findings))

    def test_issue_7863(self):
        testfile = open("unittests/scans/wfuzz/issue_7863.json")
        parser = WFuzzParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))
        self.assertEqual("Medium", findings[0].severity)

    def test_one_finding_responsecode_missing(self):
        testfile = open("unittests/scans/wfuzz/one_finding_responsecode_missing.json")
        parser = WFuzzParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))
