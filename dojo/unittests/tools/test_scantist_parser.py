from django.test import TestCase
from dojo.tools.scantist.parser import ScantistJSONParser
from dojo.models import Test


class TestScantistJSONParser(TestCase):

    def test_parse_without_file_has_no_findings(self):
        parser = ScantistJSONParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/scantist/scantist-no-vuln.json")
        parser = ScantistJSONParser(testfile, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        testfile = open("dojo/unittests/scans/scantist/scantist-one-vuln.json")
        parser = ScantistJSONParser(testfile, Test())
        self.assertEqual(1, len(parser.items))

        findings = parser.items[0]
        self.assertEqual(findings.title, findings.cve + '|' + findings.component_name)
        self.assertEqual(
            findings.description,
            "Integer overflow in the crypt_raw method in the key-stretching implementation in jBCrypt before 0.4 "
            "makes it easier for remote attackers to determine cleartext values of password hashes via a brute-force "
            "attack against hashes associated with the maximum exponent.",
        )
        self.assertEqual(
            findings.severity, "Medium"
        )  # Negligible is translated to Informational

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        testfile = open("dojo/unittests/scans/scantist/scantist-many-vuln.json")
        parser = ScantistJSONParser(testfile, Test())
        self.assertTrue(len(parser.items) > 2)
