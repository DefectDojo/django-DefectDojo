
from os import path

from django.test import TestCase
from dojo.models import Test
from dojo.tools.trivy.parser import TrivyParser


class TestTrivyParser(TestCase):

    def test_no_vuln(self):
        test_file = open(path.join(path.dirname(__file__), "scans/trivy/no_vuln.json"))
        parser = TrivyParser()
        trivy_findings = parser.get_findings(test_file, Test())
        self.assertEqual(len(trivy_findings), 0)

    def test_many_vulns(self):
        test_file = open(path.join(path.dirname(__file__), "scans/trivy/many_vulns.json"))
        parser = TrivyParser()
        findings = parser.get_findings(test_file, Test())
        self.assertEqual(len(findings), 93)
        finding = findings[0]
        self.assertEqual("Low", finding.severity)
        self.assertEqual("CVE-2011-3374", finding.cve)
        self.assertEqual(347, finding.cwe)
        self.assertEqual("apt", finding.component_name)
        self.assertEqual("1.8.2.2", finding.component_version)
