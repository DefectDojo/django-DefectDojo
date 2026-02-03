from pathlib import Path

from dojo.models import Test
from dojo.tools.cyberwatch_galeax.parser import CyberwatchGaleaxParser
from unittests.dojo_test_case import DojoTestCase


class TestCyberwatchGaleaxParser(DojoTestCase):

    def setUp(self):
        self.parser = CyberwatchGaleaxParser()
        self.test = Test()

    def test_no_findings(self):
        testfile = Path("unittests/scans/cyberwatch_galeax/no_findings.json")
        with testfile.open("rb") as file:
            findings = self.parser.get_findings(file, self.test)
            self.assertEqual(0, len(findings))

    def test_one_security_issue(self):
        testfile = Path("unittests/scans/cyberwatch_galeax/one_security_issue.json")
        with testfile.open("rb") as file:
            findings = self.parser.get_findings(file, self.test)
            self.assertEqual(1, len(findings))
            self.validate_locations(findings)
            finding = findings[0]
            self.assertEqual("Security Issue - Fingerprint Web Application Framework", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertEqual("No mitigation provided.", finding.mitigation)
            self.assertEqual("", finding.references)
            locations = [e.host for e in self.get_unsaved_locations(finding)]
            self.assertEqual(2, len(locations))
            self.assertTrue(all(host == "host" for host in locations))

    def test_one_cve(self):
        testfile = Path("unittests/scans/cyberwatch_galeax/one_cve.json")
        with testfile.open("rb") as file:
            findings = self.parser.get_findings(file, self.test)
            self.assertEqual(1, len(findings))
            self.validate_locations(findings)
            finding = findings[0]
            self.assertEqual("CVE-2023-42366", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertIn("CVSS Base vector:", finding.description)
            self.assertIn("CVE Published At: 2023-11-27T23:15:07.420+01:00", finding.description)
            self.assertIn("Exploit Code Maturity: proof_of_concept", finding.description)
            self.assertTrue(finding.mitigation.startswith("Fixed At:"))
            self.assertEqual(0.00044, finding.epss_score)
            self.assertEqual("Updated At: 2024-12-06T14:15:19.530+01:00", finding.references)
            self.assertEqual(787, finding.cwe)
            self.assertEqual(1, len(self.get_unsaved_locations(finding)))
            # Validate locations
            locations = [e.host for e in self.get_unsaved_locations(finding)]
            self.assertIn("computer_name", locations)

    def test_mixed_findings(self):
        testfile = Path("unittests/scans/cyberwatch_galeax/mixed_findings.json")
        with testfile.open("rb") as file:
            findings = self.parser.get_findings(file, self.test)

            self.assertEqual(3, len(findings))
            self.validate_locations(findings)

            cve_findings = [f for f in findings if f.title.startswith("CVE-")]
            security_issues = [f for f in findings if f.title.startswith("Security Issue")]

            self.assertEqual(1, len(cve_findings))
            self.assertEqual(2, len(security_issues))

            cve_finding = cve_findings[0]
            self.assertEqual("CVE-2023-42366", cve_finding.title)
            self.assertEqual("Medium", cve_finding.severity)
            self.assertIn("CVE Published At:", cve_finding.description)
            self.assertIn("Updated At: 2024-12-06T14:15:19.530+01:00", cve_finding.references)
            self.assertEqual(0.00044, cve_finding.epss_score)
            self.assertEqual(787, cve_finding.cwe)
            self.assertIsNone(cve_finding.component_name)
            self.assertEqual(1, len(self.get_unsaved_locations(cve_finding)))

            for sec_issue in security_issues:
                self.assertTrue(sec_issue.title.startswith("Security Issue - "))
                self.assertIn(sec_issue.severity, ["Critical", "High", "Medium", "Low", "Info"])
                self.assertTrue(len(self.get_unsaved_locations(sec_issue)) > 0)
                self.assertIsNotNone(sec_issue.description)
                self.assertIsNotNone(sec_issue.mitigation)
                self.assertIsNotNone(sec_issue.impact)
                self.assertIsNotNone(sec_issue.references)
