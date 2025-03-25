import unittest
from pathlib import Path

from dojo.models import Test
from dojo.tools.cyberwatch.parser import CyberwatchParser


class TestCyberwatchParser(unittest.TestCase):

    def setUp(self):
        self.parser = CyberwatchParser()
        self.test = Test()

    def test_no_findings(self):
        testfile = Path("unittests/scans/cyberwatch/no_findings.json")
        with testfile.open("rb") as file:
            findings = self.parser.get_findings(file, self.test)
            self.assertEqual(0, len(findings))

    def test_one_security_issue(self):
        testfile = Path("unittests/scans/cyberwatch/one_security_issue.json")
        with testfile.open("rb") as file:
            findings = self.parser.get_findings(file, self.test)
            self.assertEqual(1, len(findings))

            finding = findings[0]
            self.assertEqual("Security Issue - Fingerprint Web Application Framework", finding.title)
            self.assertEqual("Info", finding.severity)
            # Expect both endpoints to have the same host as per new JSON
            endpoint_hosts = [e.host for e in finding.unsaved_endpoints]
            self.assertEqual(2, len(endpoint_hosts))
            self.assertTrue(all(host == "host" for host in endpoint_hosts))
            self.assertEqual("No mitigation provided.", finding.mitigation)
            self.assertEqual("", finding.references)

    def test_one_cve(self):
        testfile = Path("unittests/scans/cyberwatch/one_cve.json")
        with testfile.open("rb") as file:
            findings = self.parser.get_findings(file, self.test)
            self.assertEqual(1, len(findings))

            finding = findings[0]
            # When there are no products, title equals the CVE code
            self.assertEqual("CVE-2023-42366", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertIn("CVSS Base vector:", finding.description)
            self.assertIn("CVE Published At: 2023-11-27T23:15:07.420+01:00", finding.description)
            self.assertIn("Exploit Code Maturity: proof_of_concept", finding.description)
            self.assertIn("EPSS: 0.00044", finding.description)
            # Since there are no updates_assets, mitigation is set to a string starting with "Fixed At:"
            self.assertTrue(finding.mitigation.startswith("Fixed At:"))
            self.assertEqual("Updated At: 2024-12-06T14:15:19.530+01:00", finding.references)
            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint_hosts = [e.host for e in finding.unsaved_endpoints]
            self.assertIn("computer_name", endpoint_hosts)

    def test_mixed_findings(self):
        testfile = Path("unittests/scans/cyberwatch/mixed_findings.json")
        with testfile.open("rb") as file:
            findings = self.parser.get_findings(file, self.test)

            self.assertEqual(3, len(findings))

            # Separate CVEs and Security Issues by title
            cve_findings = [f for f in findings if f.title.startswith("CVE-")]
            security_issues = [f for f in findings if f.title.startswith("Security Issue")]

            self.assertEqual(1, len(cve_findings))
            self.assertEqual(2, len(security_issues))

            # For the CVE finding, check expected properties
            cve_finding = cve_findings[0]
            self.assertEqual("CVE-2023-42366", cve_finding.title)
            self.assertEqual("Medium", cve_finding.severity)
            self.assertIn("CVE Published At:", cve_finding.description)
            self.assertIn("Updated At: 2024-12-06T14:15:19.530+01:00", cve_finding.references)
            self.assertEqual(1, len(cve_finding.unsaved_endpoints))
            self.assertIsNone(cve_finding.component_name)

            # For each security issue, check that title and severity are valid and endpoints exist
            for sec_issue in security_issues:
                self.assertTrue(sec_issue.title.startswith("Security Issue - "))
                self.assertIn(sec_issue.severity, ["Critical", "High", "Medium", "Low", "Info"])
                self.assertTrue(len(sec_issue.unsaved_endpoints) > 0)
                self.assertIsNotNone(sec_issue.description)
                self.assertIsNotNone(sec_issue.mitigation)
                self.assertIsNotNone(sec_issue.impact)
                self.assertIsNotNone(sec_issue.references)


if __name__ == "__main__":
    unittest.main()
