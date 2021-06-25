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
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(16, finding.cwe)
            self.assertIsNotNone(finding.description)
            self.assertGreater(len(finding.description), 0)
            self.assertEqual("5.5", finding.cvssv3)

    def test_parse_file_with_multiple_finding(self):
        testfile = open("dojo/unittests/scans/netsparker/netsparker_many_finding.json")
        parser = NetsparkerParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(40, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(16, finding.cwe)
            self.assertIsNotNone(finding.description)
            self.assertGreater(len(finding.description), 0)
            self.assertEqual("5.5", finding.cvssv3)

        with self.subTest(i=1):
            finding = findings[1]
            self.assertEqual("Critical", finding.severity)
            self.assertEqual(89, finding.cwe)
            self.assertIsNotNone(finding.description)
            self.assertGreater(len(finding.description), 0)
            self.assertEqual("10.0", finding.cvssv3)

        with self.subTest(i=2):
            finding = findings[2]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(205, finding.cwe)
            self.assertIsNotNone(finding.description)
            self.assertGreater(len(finding.description), 0)
            self.assertEqual("4.1", finding.cvssv3)
