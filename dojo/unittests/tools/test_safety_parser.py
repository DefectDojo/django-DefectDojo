from django.test import TestCase

from dojo.models import Test
from dojo.tools.safety.parser import SafetyParser


class TestSafetyParser(TestCase):
    def test_example_report(self):
        testfile = open("dojo/unittests/scans/safety/example_report.json")
        parser = SafetyParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(3, len(findings))

    def test_no_cve(self):
        testfile = open("dojo/unittests/scans/safety/no_cve.json")
        parser = SafetyParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_empty_report(self):
        testfile = open("dojo/unittests/scans/safety/empty.json")
        parser = SafetyParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_multiple_cves(self):
        testfile = open("dojo/unittests/scans/safety/multiple_cves.json")
        parser = SafetyParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_multiple2(self):
        testfile = open("dojo/unittests/scans/safety/many_vulns.json")
        parser = SafetyParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(5, len(findings))
        for finding in findings:
            if "39608" == finding.unique_id_from_tool:
                self.assertEqual("httplib2", finding.component_name)
                self.assertEqual("0.18.1", finding.component_version)
