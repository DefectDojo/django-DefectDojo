
from dojo.models import Test
from dojo.tools.cycognito.parser import CycognitoParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestCycognitoParser(DojoTestCase):
    def setup(self, testfile):
        parser = CycognitoParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        return findings

    def test_cycognito_has_no_findings_json(self):
        findings = self.setup(
            (get_unit_tests_scans_path("cycognito") / "no_vuln.json").open(encoding="utf-8"))
        self.assertEqual(0, len(findings))

    def test_cycognito_one_finding_json(self):
        findings = self.setup(
            (get_unit_tests_scans_path("cycognito") / "one_vuln.json").open(encoding="utf-8"))
        self.assertEqual(1, len(findings))
        self.validate_locations(findings)
        finding = findings[0]
        self.assertEqual(finding.title, "Diffie-Hellman Ephemeral Key Exchange DoS Vulnerability (SSH, D(HE)ater)")
        self.assertEqual(finding.references, "https://dheatattack.gitlab.io/")

    def test_cycognito_has_many_findings_json(self):
        findings = self.setup(
            (get_unit_tests_scans_path("cycognito") / "many_vuln.json").open(encoding="utf-8"))
        self.assertEqual(3, len(findings))
        self.validate_locations(findings)
        finding = findings[1]
        self.assertEqual(finding.title, "Diffie-Hellman Ephemeral Key Exchange DoS Vulnerability (SSL/TLS, D(HE)ater)")
        self.assertEqual(finding.date, "2025-05-16")
        self.assertEqual(finding.severity, "Medium")
        finding = findings[2]
        self.assertEqual(finding.title, "Diffie-Hellman Ephemeral Key Exchange DoS Vulnerability (SSH, D(HE)ater)")
        self.assertEqual(finding.date, "2025-05-15")
        self.assertEqual(finding.severity, "Medium")
