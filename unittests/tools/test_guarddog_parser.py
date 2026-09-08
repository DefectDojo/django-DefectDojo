from dojo.models import Test
from dojo.tools.guarddog.parser import GuardDogParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestGuardDogParser(DojoTestCase):

    def test_parse_no_findings(self):
        """GuardDog lists every rule it ran, with an empty result for the ones that missed."""
        with (get_unit_tests_scans_path("guarddog") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = GuardDogParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("guarddog") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = GuardDogParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("threat-setup-network-in-install in fakepkg", finding.title)
            self.assertEqual("threat-setup-network-in-install", finding.vuln_id_from_tool)
            self.assertEqual("setup.py", finding.file_path)
            self.assertEqual(9, finding.line)
            self.assertEqual("fakepkg", finding.component_name)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

            with self.subTest("severity comes from the correlated risk, not the rule family"):
                self.assertEqual("High", finding.severity)

            with self.subTest("the risk's own context reaches the description"):
                self.assertIn("**MITRE tactics:** exfiltration", finding.description)
                self.assertIn("**Category:** network", finding.description)
                self.assertIn("**Package risk:** high_risk", finding.description)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("guarddog") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = GuardDogParser().get_findings(testfile, Test())
            self.assertEqual(4, len(findings))

            with self.subTest("an uncorrelated capability is only an observation"):
                capabilities = [f for f in findings if f.vuln_id_from_tool.startswith("capability-")]
                self.assertEqual(3, len(capabilities))
                self.assertEqual({"Info"}, {f.severity for f in capabilities})

            with self.subTest("the correlated threat rule is High"):
                threats = [f for f in findings if f.vuln_id_from_tool.startswith("threat-")]
                self.assertEqual(1, len(threats))
                self.assertEqual("High", threats[0].severity)

            with self.subTest("every finding is anchored in the package source"):
                for finding in findings:
                    self.assertEqual("setup.py", finding.file_path)
                    self.assertIsNotNone(finding.line)

    def test_severity_falls_back_to_the_rule_family(self):
        parser = GuardDogParser()
        self.assertEqual("High", parser._severity("threat-x", {"severity": "high"}))
        self.assertEqual("Low", parser._severity("threat-x", {"severity": "low"}))
        # An uncorrelated rule has no risk entry at all.
        self.assertEqual("Info", parser._severity("capability-process-spawn", None))
        self.assertEqual("Medium", parser._severity("threat-setup-network-in-install", None))
