from os import path

from django.test import TestCase
from dojo.models import Test
from dojo.tools.cobalt.parser import CobaltParser


class TestCobaltParser(TestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):

        testfile = open(path.join(path.dirname(__file__), "scans/cobalt/cobalt_no_vuln.csv"))
        parser = CobaltParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        testfile = open(path.join(path.dirname(__file__), "scans/cobalt/cobalt_one_vuln.csv"))
        parser = CobaltParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        testfile = open(path.join(path.dirname(__file__), "scans/cobalt/cobalt_many_vuln.csv"))
        parser = CobaltParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(9, len(findings))
