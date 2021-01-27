from django.test import TestCase

from dojo.models import Test
from dojo.tools.safety.parser import SafetyParser


class TestSafetyParser(TestCase):
    def test_example_report(self):
        testfile = "dojo/unittests/scans/safety/example_report.json"
        with open(testfile) as f:
            parser = SafetyParser(f, Test())
        self.assertEqual(3, len(findings))
        for item in findings:
            self.assertIsNotNone(item.cve)

    def test_no_cve(self):
        testfile = "dojo/unittests/scans/safety/no_cve.json"
        with open(testfile) as f:
            parser = SafetyParser(f, Test())
        self.assertEqual(1, len(findings))
        self.assertIsNone(findings[0].cve)

    def test_empty_report(self):
        testfile = "dojo/unittests/scans/safety/empty.json"
        with open(testfile) as f:
            parser = SafetyParser(f, Test())
        self.assertEqual(0, len(findings))

    def test_multiple_cves(self):
        testfile = "dojo/unittests/scans/safety/multiple_cves.json"
        with open(testfile) as f:
            parser = SafetyParser(f, Test())
        self.assertEqual(1, len(findings))
        cves = findings[0].cve.split(',')
        self.assertEqual(2, len(cves))
