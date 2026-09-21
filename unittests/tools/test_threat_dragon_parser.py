from dojo.models import Test
from dojo.tools.threat_dragon.parser import ThreatDragonParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestThreatDragonParser(DojoTestCase):

    def test_parse_no_findings(self):
        """Diagram cells that carry no threats produce nothing."""
        with (get_unit_tests_scans_path("threat_dragon") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = ThreatDragonParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("threat_dragon") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = ThreatDragonParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Accessing DB credentials", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("Worker Config", finding.component_name)
            self.assertTrue(finding.active)
            self.assertFalse(finding.is_mitigated)
            self.assertIn("**Threat type:** Information disclosure", finding.description)
            self.assertIn("**Element:** Worker Config", finding.description)
            self.assertIn("**Model:** Example Threat Model", finding.description)
            self.assertIn("Encrypt the DB credentials", finding.mitigation)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("threat_dragon") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = ThreatDragonParser().get_findings(testfile, Test())
            self.assertEqual(14, len(findings))

            with self.subTest("the model's own severities are preserved"):
                self.assertEqual(8, len([f for f in findings if f.severity == "High"]))
                self.assertEqual(4, len([f for f in findings if f.severity == "Medium"]))
                self.assertEqual(2, len([f for f in findings if f.severity == "Low"]))

            with self.subTest("threats already addressed import as mitigated, not dropped"):
                mitigated = [f for f in findings if f.is_mitigated]
                self.assertEqual(4, len(mitigated))
                for finding in mitigated:
                    self.assertFalse(finding.active)
                    self.assertIn("**Status:** Mitigated", finding.description)

            with self.subTest("open threats stay active"):
                self.assertEqual(10, len([f for f in findings if f.active]))

            with self.subTest("STRIDE categories reach the description"):
                types = {t for f in findings for t in ("Spoofing", "Tampering", "Denial of service")
                         if f"**Threat type:** {t}" in f.description}
                self.assertEqual({"Spoofing", "Tampering", "Denial of service"}, types)

    def test_element_name_falls_back_across_schema_versions(self):
        parser = ThreatDragonParser()
        self.assertEqual("v1 name", parser._element_name({"attrs": {"text": {"text": "v1 name"}}}))
        self.assertEqual("v2 name", parser._element_name({"data": {"name": "v2 name"}}))
        self.assertEqual("labelled", parser._element_name({"label": "labelled"}))
        self.assertIsNone(parser._element_name({}))
