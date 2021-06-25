from django.test import TestCase
from dojo.models import Test
from dojo.tools.netsparker.parser import NetsparkerParser


class TestNetsparkerParser(TestCase):

    def test_parse_file_with_one_finding(self):
        testfile = open("dojo/unittests/scans/netsparker/netsparker_one_finding.json")
        parser = NetsparkerParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Medium", finding["Severity"])
            self.assertEqual(16, finding["Classification"]["Cwe"])
            self.assertIsNotNone(finding["Description"])
            self.assertGreater(len(finding["Description"]), 0)

    def test_parse_file_with_multiple_finding(self):
        testfile = open("dojo/unittests/scans/netsparker/netsparker_one_finding.json")
        parser = NetsparkerParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Medium", finding["Severity"])
            self.assertEqual(16, finding["Classification"]["Cwe"])
            self.assertIsNotNone(finding["Description"])
            self.assertGreater(len(finding["Description"]), 0)
            self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N/E:H/RL:O/RC:C", finding["Classification"]["Cvss"]["Vector"])

        with self.subTest(i=1):
            finding = findings[1]
            self.assertEqual("Critical", finding["Severity"])
            self.assertEqual(205, finding["Classification"]["Cwe"])
            self.assertIsNotNone(finding["Description"])
            self.assertGreater(len(finding["Description"]), 0)
            self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", finding["Classification"]["Cvss"]["Vector"])

        with self.subTest(i=2):
            finding = findings[2]
            self.assertEqual("Medium", finding["Severity"])
            self.assertEqual(205, finding["Classification"]["Cwe"])
            self.assertIsNotNone(finding["Description"])
            self.assertGreater(len(finding["Description"]), 0)
            self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N/E:H/RL:O/RC:C", finding["Classification"]["Cvss"]["Vector"])
