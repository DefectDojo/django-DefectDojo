from dojo.models import Finding, Test
from dojo.tools.dectrax.parser import DectraxParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDectraxParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("dectrax") / filename).open(encoding="utf-8") as file:
            return list(DectraxParser().get_findings(file, Test()))

    def test_scan_type(self):
        parser = DectraxParser()
        self.assertEqual(["DECTRAX Deception Scan"], parser.get_scan_types())
        self.assertEqual("DECTRAX Deception Scan", parser.get_label_for_scan_types("DECTRAX Deception Scan"))
        self.assertIn("deception", parser.get_description_for_scan_types("DECTRAX Deception Scan").lower())

    def test_zero_findings(self):
        findings = self.parse("dectrax_zero_vuln.json")
        self.assertEqual(0, len(findings))

    def test_one_finding(self):
        findings = self.parse("dectrax_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Decoy SSH Credential Abuse & Reconnaissance", finding.title)
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("DECTRAX-INC-2026-001", finding.unique_id_from_tool)
        self.assertEqual("T1110.001", finding.vuln_id_from_tool)
        self.assertEqual(287, finding.cwe)
        self.assertFalse(finding.false_p)
        self.assertTrue(finding.active)
        self.assertTrue(finding.dynamic_finding)
        self.assertFalse(finding.static_finding)
        self.assertIn("canary-token", finding.unsaved_tags)
        self.assertIn("deception", finding.unsaved_tags)

    def test_many_findings(self):
        findings = self.parse("dectrax_many_vuln.json")
        self.assertEqual(3, len(findings))

        severities = [f.severity for f in findings]
        self.assertEqual(["High", "Critical", "Medium"], severities)
