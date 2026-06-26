from dojo.models import Test
from dojo.tools.orca_security.parser import OrcaSecurityParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestOrcaSecurityParser(DojoTestCase):

    # --- CSV Tests ---

    def test_parse_csv_no_findings(self):
        with (get_unit_tests_scans_path("orca_security") / "no_vuln.csv").open(encoding="utf-8") as testfile:
            parser = OrcaSecurityParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_csv_one_finding(self):
        with (get_unit_tests_scans_path("orca_security") / "one_vuln.csv").open(encoding="utf-8") as testfile:
            parser = OrcaSecurityParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Unused role with policy found", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertTrue(finding.active)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)
            self.assertEqual("TestRole_abc123", finding.component_name)
            self.assertEqual("TestRole_abc123", finding.service)
            self.assertEqual("OrcaScore: 5.1", finding.severity_justification)
            self.assertIn("IAM misconfigurations", finding.description)
            self.assertEqual(["CSPM", "source: Orca Scan"], finding.unsaved_tags)

    def test_parse_csv_many_findings(self):
        with (get_unit_tests_scans_path("orca_security") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = OrcaSecurityParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(5, len(findings))

            # Check severity mapping across all levels
            severities = [f.severity for f in findings]
            self.assertIn("Low", severities)
            self.assertIn("Medium", severities)
            self.assertIn("High", severities)
            self.assertIn("Critical", severities)
            self.assertIn("Info", severities)

            # Check inactive finding (last one, status=closed)
            closed_finding = findings[4]
            self.assertFalse(closed_finding.active)
            self.assertEqual("Info", closed_finding.severity)

    # --- JSON Tests ---

    def test_parse_json_no_findings(self):
        with (get_unit_tests_scans_path("orca_security") / "no_vuln.json").open(encoding="utf-8") as testfile:
            parser = OrcaSecurityParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_json_one_finding(self):
        with (get_unit_tests_scans_path("orca_security") / "one_vuln.json").open(encoding="utf-8") as testfile:
            parser = OrcaSecurityParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Unused role with policy found", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertTrue(finding.active)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)
            self.assertEqual("TestRole_abc123", finding.component_name)
            self.assertEqual("TestRole_abc123", finding.service)
            self.assertEqual("OrcaScore: 5.1", finding.severity_justification)
            self.assertIn("IAM misconfigurations", finding.description)
            self.assertEqual(["CSPM", "source: Orca Scan"], finding.unsaved_tags)

    def test_parse_json_many_findings(self):
        with (get_unit_tests_scans_path("orca_security") / "many_vulns.json").open(encoding="utf-8") as testfile:
            parser = OrcaSecurityParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(5, len(findings))

            # Check severity mapping across all levels
            severities = [f.severity for f in findings]
            self.assertIn("Low", severities)
            self.assertIn("Medium", severities)
            self.assertIn("High", severities)
            self.assertIn("Critical", severities)
            self.assertIn("Info", severities)

            # Check inactive finding (last one, status=closed)
            closed_finding = findings[4]
            self.assertFalse(closed_finding.active)
            self.assertEqual("Info", closed_finding.severity)

    # --- Cross-format consistency tests ---

    def test_date_is_parsed(self):
        """CreatedAt should be parsed into a date object."""
        with (get_unit_tests_scans_path("orca_security") / "one_vuln.json").open(encoding="utf-8") as testfile:
            parser = OrcaSecurityParser()
            findings = parser.get_findings(testfile, Test())
            finding = findings[0]
            self.assertIsNotNone(finding.date)
            self.assertEqual(2025, finding.date.year)
            self.assertEqual(1, finding.date.month)
            self.assertEqual(15, finding.date.day)
