import datetime

from django.test import SimpleTestCase
from dojo.tools.veracode.parser import VeracodeParser
from dojo.models import Test


class TestVeracodeScannerParser(SimpleTestCase):

    def test_parse_file_with_one_finding(self):
        testfile = open("dojo/unittests/scans/veracode/one_finding.xml")
        parser = VeracodeParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_finding(self):
        testfile = open("dojo/unittests/scans/veracode/many_findings.xml")
        parser = VeracodeParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(3, len(findings))
        finding = findings[0]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual(123, finding.cwe)

    def test_parse_file_with_multiple_finding2(self):
        testfile = open("dojo/unittests/scans/veracode/veracode_scan.xml")
        parser = VeracodeParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(4, len(findings))
        finding = findings[0]
        self.assertEqual("Low", finding.severity)
        self.assertEqual(201, finding.cwe)
        finding = findings[1]
        self.assertEqual("Low", finding.severity)
        self.assertEqual(201, finding.cwe)

    def test_parse_file_with_mitigated_finding(self):
        testfile = open("dojo/unittests/scans/veracode/mitigated_finding.xml")
        parser = VeracodeParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("Medium", finding.severity)
        self.assertTrue(finding.is_Mitigated)
        self.assertEqual(datetime.datetime(2020, 6, 1, 10, 2, 1), finding.mitigated)
