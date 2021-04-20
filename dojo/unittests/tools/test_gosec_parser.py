from os import path

from django.test import TestCase
from dojo.models import Test
from dojo.tools.gosec.parser import GosecParser


class TestGosecParser(TestCase):

    def test_parse_file_with_one_finding(self):
        testfile = open(path.join(path.dirname(__file__), "scans/gosec/many_vulns.json"))
        parser = GosecParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(28, len(findings))
        finding = findings[0]
        self.assertEqual("Low", finding.severity)
        self.assertEqual("/vagrant/go/src/govwa/app.go", finding.file_path)
        self.assertEqual(79, finding.line)
