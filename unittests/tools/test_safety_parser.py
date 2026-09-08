from dojo.models import Test
from dojo.tools.safety.parser import SafetyParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSafetyParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("safety") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = SafetyParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        """A PVE advisory carries neither a CVE nor a severity."""
        with (get_unit_tests_scans_path("safety") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = SafetyParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("insecure-package: 25853", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("25853", finding.vuln_id_from_tool)
            self.assertEqual("insecure-package", finding.component_name)
            self.assertEqual("0.1.0", finding.component_version)
            self.assertIn("**Vulnerable spec:** <0.2.0", finding.description)
            self.assertIn("**Safety version:** 2.0b1", finding.description)
            self.assertIn("pyup.io", finding.references)
            # This advisory lists no usable fixed version, so no upgrade can be named.
            self.assertIsNone(finding.mitigation)
            self.assertFalse(getattr(finding, "unsaved_vulnerability_ids", None))
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("safety") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = SafetyParser().get_findings(testfile, Test())

            with self.subTest("advisories Safety flags as ignored are not imported"):
                self.assertEqual(2, len(findings))
                self.assertNotIn("11111", {f.vuln_id_from_tool for f in findings})

            with self.subTest("a CVE-bearing advisory keeps its severity and vulnerability id"):
                cve_finding = next(f for f in findings if f.vuln_id_from_tool == "38765")
                self.assertEqual("High", cve_finding.severity)
                self.assertEqual(["CVE-2021-33503"], cve_finding.unsaved_vulnerability_ids)
                self.assertEqual("Upgrade example-lib to 1.2.1.", cve_finding.mitigation)
                self.assertEqual("1.2.0", cve_finding.component_version)
