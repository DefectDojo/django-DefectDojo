from ..dojo_test_case import DojoTestCase
from dojo.tools.scantist.parser import ScantistParser
from dojo.models import Test


class TestScantistParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/scantist/scantist-no-vuln.json")
        parser = ScantistParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        testfile = open("unittests/scans/scantist/scantist-one-vuln.json")
        parser = ScantistParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

        findings = findings[0]
        self.assertEqual(findings.title, findings.unsaved_vulnerability_ids[0] + "|" + findings.component_name)
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
        testfile = open("unittests/scans/scantist/scantist-many-vuln.json")
        parser = ScantistParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(17, len(findings))
        finding = findings[0]
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2018-12432", finding.unsaved_vulnerability_ids[0])
