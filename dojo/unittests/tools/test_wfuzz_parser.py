from os import path

from django.test import TestCase
from dojo.models import Test
from dojo.tools.wfuzz.parser import WFuzzParser


class TestWFuzzParser(TestCase):

    def test_parse_no_findings(self):
        testfile = open(path.join(path.dirname(__file__), "scans/wfuzz/no_findings.json"))
        parser = WFuzzParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        testfile = open(path.join(path.dirname(__file__), "scans/wfuzz/one_finding.json"))
        parser = WFuzzParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_many_finding(self):
        testfile = open(path.join(path.dirname(__file__), "scans/wfuzz/many_findings.json"))
        parser = WFuzzParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(4, len(findings))

    def test_one_dup_finding(self):
        testfile = open(path.join(path.dirname(__file__), "scans/wfuzz/one_dup_finding.json"))
        parser = WFuzzParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(4, len(findings))
