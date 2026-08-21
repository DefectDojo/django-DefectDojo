from dojo.models import Test
from dojo.tools.picus.parser import PicusParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestPicusParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("picus") / "no_vuln.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("picus") / "one_vuln.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("picus") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(6, len(findings))

    def test_title_combines_threat_and_action(self):
        with (get_unit_tests_scans_path("picus") / "one_vuln.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(
                "Fileless Malware via PowerShell - PowerShell Download Cradle Execution",
                findings[0].title,
            )

    def test_severity_critical(self):
        with (get_unit_tests_scans_path("picus") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("Critical", findings[0].severity)

    def test_severity_high(self):
        with (get_unit_tests_scans_path("picus") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("High", findings[1].severity)

    def test_severity_medium(self):
        with (get_unit_tests_scans_path("picus") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("Medium", findings[2].severity)

    def test_severity_low(self):
        with (get_unit_tests_scans_path("picus") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("Low", findings[3].severity)

    def test_severity_uses_threat_severity_not_action_severity(self):
        # Row 0 has threatSeverity=Critical but action-level severity=High.
        with (get_unit_tests_scans_path("picus") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("Critical", findings[0].severity)

    def test_active_when_not_blocked(self):
        with (get_unit_tests_scans_path("picus") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            self.assertTrue(findings[0].active)

    def test_inactive_when_blocked(self):
        with (get_unit_tests_scans_path("picus") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            self.assertFalse(findings[1].active)

    def test_vuln_id_from_action_id(self):
        with (get_unit_tests_scans_path("picus") / "one_vuln.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("1001", findings[0].vuln_id_from_tool)

    def test_cve_extracted(self):
        with (get_unit_tests_scans_path("picus") / "one_vuln.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(["CVE-2021-44228"], findings[0].unsaved_vulnerability_ids)

    def test_cwe_extracted(self):
        with (get_unit_tests_scans_path("picus") / "one_vuln.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(78, findings[0].cwe)

    def test_no_cve_when_field_empty(self):
        with (get_unit_tests_scans_path("picus") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            # Row index 1 (Credential Dumping) has no CVE.
            self.assertIsNone(findings[1].unsaved_vulnerability_ids)

    def test_mitre_tags(self):
        with (get_unit_tests_scans_path("picus") / "one_vuln.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(
                ["TA0002", "T1059", "T1059.001", "Malicious Code"],
                findings[0].unsaved_tags,
            )

    def test_component_name_from_affected_products(self):
        with (get_unit_tests_scans_path("picus") / "one_vuln.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("Product Y", findings[0].component_name)

    def test_title_truncated_at_500_chars(self):
        with (get_unit_tests_scans_path("picus") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            # Row index 4 has 300+300 char threat/action names.
            self.assertEqual(500, len(findings[4].title))
            self.assertTrue(findings[4].title.endswith("..."))

    def test_static_and_dynamic_flags(self):
        with (get_unit_tests_scans_path("picus") / "one_vuln.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            self.assertFalse(findings[0].static_finding)
            self.assertTrue(findings[0].dynamic_finding)

    def test_description_is_markdown_table(self):
        with (get_unit_tests_scans_path("picus") / "one_vuln.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIn("| Field | Value |", findings[0].description)
            self.assertIn("| Attack Category | Malicious Code |", findings[0].description)

    def test_mitigation_not_blocked_sentence(self):
        with (get_unit_tests_scans_path("picus") / "one_vuln.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIn("was NOT blocked by existing preventive controls", findings[0].mitigation)

    def test_mitigation_blocked_sentence(self):
        with (get_unit_tests_scans_path("picus") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            # Row index 1 (Credential Dumping) was Blocked.
            self.assertIn("was blocked by existing preventive controls", findings[1].mitigation)

    def test_mitigation_includes_control_posture(self):
        with (get_unit_tests_scans_path("picus") / "one_vuln.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            mitigation = findings[0].mitigation
            self.assertIn("**Control posture**", mitigation)
            self.assertIn("- Prevention: Not Blocked", mitigation)
            self.assertIn("- Logging: Not Logged", mitigation)
            self.assertIn("- Alerting: Not Alerted", mitigation)

    def test_mitigation_includes_reference_links(self):
        with (get_unit_tests_scans_path("picus") / "one_vuln.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            mitigation = findings[0].mitigation
            self.assertIn("**Mitigation & triage references**", mitigation)
            self.assertIn("- Picus mitigation guidance: https://sample[.]com", mitigation)
            self.assertIn("- Detection content: https://sample[.]com", mitigation)
            self.assertIn("- Action payload output: https://sample[.]com", mitigation)
            self.assertIn("- Action logs: https://sample[.]com", mitigation)
            self.assertIn("- Detection signature: SIG-T1059 (10001001)", mitigation)

    def test_mitigation_omits_absent_reference_fields(self):
        with (get_unit_tests_scans_path("picus") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = PicusParser()
            findings = parser.get_findings(testfile, Test())
            # many_vulns.csv leaves detection-content / payload-output links empty.
            mitigation = findings[0].mitigation
            self.assertNotIn("- Detection content:", mitigation)
            self.assertNotIn("- Action payload output:", mitigation)
