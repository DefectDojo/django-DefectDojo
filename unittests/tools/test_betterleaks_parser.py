from django.test import TestCase
from dojo.models import Test
from dojo.tools.betterleaks.parser import BetterleaksParser


class TestBetterleaksParser(TestCase):
    def test_betterleaks_parser_one_finding(self):
        testfile = open("unittests/scans/betterleaks/betterleaks_one_finding.json")
        parser = BetterleaksParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.severity, "High")
        self.assertEqual(finding.file_path, "file.cfg")
        self.assertEqual(finding.line, 53)
        self.assertEqual(finding.cwe, 798)