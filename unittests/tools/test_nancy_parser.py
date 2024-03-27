from os import path
from ..dojo_test_case import DojoTestCase
from dojo.tools.nancy.parser import NancyParser
from dojo.models import Test


class TestNancyParser(DojoTestCase):
    def test_nancy_parser_with_no_vuln_has_no_findings(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/nancy/nancy_no_findings.json"))
        parser = NancyParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_nancy_parser_with_one_vuln_has_one_findings(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/nancy/nancy_one_findings.json"))
        parser = NancyParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual('Info', finding.severity)
            self.assertIsNotNone(finding.description)
            self.assertGreater(len(finding.description), 0)
            self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", finding.cvssv3)

    def test_nancy_plus_parser_with_many_vuln_has_many_findings(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/nancy/nancy_many_findings.json"))
        parser = NancyParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(13, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual(0, finding.cwe)
            self.assertIsNotNone(finding.description)
            self.assertGreater(len(finding.description), 0)
