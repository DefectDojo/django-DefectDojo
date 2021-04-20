from os import path

from django.test import TestCase
from dojo.models import Test
from dojo.tools.trufflehog.parser import TruffleHogParser


class TestTruffleHogParser(TestCase):

    def test_many_vulns(self):
        test_file = open(path.join(path.dirname(__file__), "scans/trufflehog/many_vulns.json"))
        parser = TruffleHogParser()
        findings = parser.get_findings(test_file, Test())
        self.assertEqual(len(findings), 18)
        finding = findings[0]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual(798, finding.cwe)
        self.assertEqual('test_all.py', finding.file_path)
