from django.test import TestCase

from dojo.models import Test
from dojo.tools.safety.parser import SafetyParser


class TestSafetyParser(TestCase):
    def test_example_report(self):
        testfile = open("dojo/unittests/scans/safety/example_report.json")
        parser = SafetyParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(3, len(findings))
        for item in findings:
            self.assertIsNotNone(item.cve)

    def test_no_cve(self):
        testfile = open("dojo/unittests/scans/safety/no_cve.json")
        parser = SafetyParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        self.assertIsNone(findings[0].cve)

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
        self.assertEqual("CVE-2019-12385", findings[0].cve)
