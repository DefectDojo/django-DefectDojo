from django.test import TestCase
from dojo.tools.nessus.parser import NessusXMLParser, NessusCSVParser, get_text_severity
from dojo.models import Finding, Test, Engagement, Product


class TestNessusParser(TestCase):

    def create_test(self):
        self.test = Test()
        self.test.engagement = Engagement()
        self.test.engagement.product = Product()

    def test_parse_without_file_has_no_findings(self):
        parser = NessusXMLParser(None, self.create_test())
        findings = parser.items
        self.assertEqual(0, len(findings))

    def test_parse_some_findings(self):
        testfile = open("dojo/unittests/scans/nessus/nessus_many_vuln.xml")
        parser = NessusXMLParser(testfile, self.create_test())
        findings = parser.items
        self.assertEqual(6, len(findings))
        finding = findings[0]
        self.assertEqual('Info', finding.severity)
        self.assertIsNone(finding.cwe)

    def test_get_text_severity(self):
        with self.subTest(val=1):
            self.assertEqual('Low', get_text_severity(1))
            self.assertIn(get_text_severity(1), Finding.SEVERITIES)
        with self.subTest(val=4):
            self.assertEqual('Critical', get_text_severity(4))
            self.assertIn(get_text_severity(4), Finding.SEVERITIES)
        with self.subTest(val=None):
            self.assertEqual('Info', get_text_severity(None))
            self.assertIn(get_text_severity(None), Finding.SEVERITIES)

    def test_parse_without_file_has_no_findings_csv(self):
        parser = NessusCSVParser(None, self.create_test())
        findings = parser.items
        self.assertEqual(0, len(findings))

    def test_parse_some_findings_csv(self):
        testfile = open("dojo/unittests/scans/nessus/nessus_many_vuln.csv")
        parser = NessusCSVParser(testfile, self.create_test())
        findings = parser.items
        self.assertEqual(6, len(findings))
        finding = findings[0]
        self.assertEqual('Info', finding.severity)
        self.assertIsNone(finding.cwe)

    def test_parse_some_findings_csv2(self):
        testfile = open("dojo/unittests/scans/nessus/nessus_many_vuln2-default.csv")
        parser = NessusCSVParser(testfile, self.create_test())
        findings = parser.items
        self.assertEqual(25, len(findings))
        finding = findings[0]
        self.assertEqual('Info', finding.severity)
        self.assertIsNone(finding.cwe)
