from dojo.models import Test
from dojo.tools.iriusrisk.parser import IriusriskParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestIriusriskParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("iriusrisk") / "no_vuln.csv").open(encoding="utf-8") as testfile:
            parser = IriusriskParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("iriusrisk") / "one_vuln.csv").open(encoding="utf-8") as testfile:
            parser = IriusriskParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("iriusrisk") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = IriusriskParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(6, len(findings))

    def test_finding_severity_high(self):
        with (get_unit_tests_scans_path("iriusrisk") / "one_vuln.csv").open(encoding="utf-8") as testfile:
            parser = IriusriskParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("High", findings[0].severity)

    def test_finding_severity_medium(self):
        with (get_unit_tests_scans_path("iriusrisk") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = IriusriskParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("Medium", findings[1].severity)

    def test_finding_severity_low(self):
        with (get_unit_tests_scans_path("iriusrisk") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = IriusriskParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("Low", findings[2].severity)

    def test_finding_severity_very_low_maps_to_info(self):
        with (get_unit_tests_scans_path("iriusrisk") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = IriusriskParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("Info", findings[3].severity)

    def test_finding_severity_critical(self):
        with (get_unit_tests_scans_path("iriusrisk") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = IriusriskParser()
            findings = parser.get_findings(testfile, Test())
            # Row 6 (index 5) has Current Risk = "Critical"
            self.assertEqual("Critical", findings[5].severity)

    def test_finding_title_truncated_at_150_chars(self):
        with (get_unit_tests_scans_path("iriusrisk") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = IriusriskParser()
            findings = parser.get_findings(testfile, Test())
            self.assertLessEqual(len(findings[4].title), 150)
            self.assertTrue(findings[4].title.endswith("..."))

    def test_finding_title_not_truncated_when_short(self):
        with (get_unit_tests_scans_path("iriusrisk") / "one_vuln.csv").open(encoding="utf-8") as testfile:
            parser = IriusriskParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("Accessing functionality not properly constrained by ACLs", findings[0].title)

    def test_finding_component_name(self):
        with (get_unit_tests_scans_path("iriusrisk") / "one_vuln.csv").open(encoding="utf-8") as testfile:
            parser = IriusriskParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("Router", findings[0].component_name)

    def test_finding_description_contains_all_fields(self):
        with (get_unit_tests_scans_path("iriusrisk") / "one_vuln.csv").open(encoding="utf-8") as testfile:
            parser = IriusriskParser()
            findings = parser.get_findings(testfile, Test())
            desc = findings[0].description
            self.assertIn("Accessing functionality not properly constrained by ACLs", desc)
            self.assertIn("Router", desc)
            self.assertIn("Elevation of Privilege", desc)
            self.assertIn("Created by Rules Engine", desc)
            self.assertIn("High", desc)

    def test_finding_mitigation(self):
        with (get_unit_tests_scans_path("iriusrisk") / "one_vuln.csv").open(encoding="utf-8") as testfile:
            parser = IriusriskParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(
                "Planned mitigation: 0%. Mitigated: 0%. Unmitigated: 100%.",
                findings[0].mitigation,
            )

    def test_finding_active_when_risk_not_very_low(self):
        with (get_unit_tests_scans_path("iriusrisk") / "one_vuln.csv").open(encoding="utf-8") as testfile:
            parser = IriusriskParser()
            findings = parser.get_findings(testfile, Test())
            self.assertTrue(findings[0].active)

    def test_finding_inactive_when_very_low(self):
        with (get_unit_tests_scans_path("iriusrisk") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = IriusriskParser()
            findings = parser.get_findings(testfile, Test())
            self.assertFalse(findings[3].active)

    def test_finding_static_finding(self):
        with (get_unit_tests_scans_path("iriusrisk") / "one_vuln.csv").open(encoding="utf-8") as testfile:
            parser = IriusriskParser()
            findings = parser.get_findings(testfile, Test())
            self.assertFalse(findings[0].static_finding)
            self.assertFalse(findings[0].dynamic_finding)

    def test_finding_with_owner(self):
        with (get_unit_tests_scans_path("iriusrisk") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = IriusriskParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIn("John Smith", findings[4].description)

    def test_finding_with_empty_owner(self):
        with (get_unit_tests_scans_path("iriusrisk") / "one_vuln.csv").open(encoding="utf-8") as testfile:
            parser = IriusriskParser()
            findings = parser.get_findings(testfile, Test())
            self.assertNotIn("None", findings[0].description)

    def test_finding_cwe_from_mitre_reference(self):
        with (get_unit_tests_scans_path("iriusrisk") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = IriusriskParser()
            findings = parser.get_findings(testfile, Test())
            # Row 1 (index 0) has MITRE reference = "CWE-284"
            self.assertEqual(284, findings[0].cwe)

    def test_finding_references_from_mitre_reference(self):
        with (get_unit_tests_scans_path("iriusrisk") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = IriusriskParser()
            findings = parser.get_findings(testfile, Test())
            # Row 2 (index 1) has MITRE reference = "T1059" (not a CWE)
            self.assertEqual("T1059", findings[1].references)

    def test_finding_stride_lm_in_description(self):
        with (get_unit_tests_scans_path("iriusrisk") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = IriusriskParser()
            findings = parser.get_findings(testfile, Test())
            # Row 1 (index 0) has STRIDE-LM = "Elevation of Privilege"
            self.assertIn("STRIDE-LM", findings[0].description)
            self.assertIn("Elevation of Privilege", findings[0].description)
