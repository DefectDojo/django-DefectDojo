from django.test import TestCase

from dojo.models import Test
from dojo.tools.sarif.parser import SarifParser


class TestSafetyParser(TestCase):
    def test_example_report(self):
        testfile = "dojo/unittests/scans/sarif/179-311.json"
        with open(testfile) as f:
            parser = SafetyParser(f, Test())
        self.assertEqual(3, len(parser.items))
        for item in parser.items:
            self.assertIsNotNone(item.cve)

    def test_example2_report(self):
        testfile = "dojo/unittests/scans/sarif/314-338.json"
        with open(testfile) as f:
            parser = SafetyParser(f, Test())
        self.assertEqual(3, len(parser.items))
        for item in parser.items:
            self.assertIsNotNone(item.cve)
