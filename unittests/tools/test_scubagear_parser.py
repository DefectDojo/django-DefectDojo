from dojo.models import Test
from dojo.tools.scubagear.parser import ScubaGearParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestScubaGearParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("scubagear") / "no_findings.csv").open(encoding="utf-8") as testfile:
            findings = ScubaGearParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("scubagear") / "one_finding.csv").open(encoding="utf-8") as testfile:
            findings = ScubaGearParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("MS.AAD.3.1v1", finding.vuln_id_from_tool)
            self.assertEqual("High", finding.severity)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

            with self.subTest("the byte order mark does not leak into the first column"):
                self.assertTrue(finding.title.startswith("MS.AAD.3.1v1: "))
                self.assertNotIn("﻿", finding.title)

            with self.subTest("report markup is stripped"):
                self.assertNotIn("<", finding.title)
                self.assertNotIn("<", finding.description)
                self.assertNotIn("policy-indicators", finding.description)
                self.assertIn("Phishing-resistant MFA SHALL be enforced", finding.title)

            with self.subTest("result and criticality reach the description"):
                self.assertIn("**Result:** Fail", finding.description)
                self.assertIn("**Criticality:** Shall", finding.description)

    def test_parse_many_findings(self):
        """The action plan holds only controls that did not pass, all mandatory here."""
        with (get_unit_tests_scans_path("scubagear") / "many_findings.csv").open(encoding="utf-8") as testfile:
            findings = ScubaGearParser().get_findings(testfile, Test())
            self.assertEqual(14, len(findings))
            self.assertEqual({"High"}, {f.severity for f in findings})

            with self.subTest("controls span several M365 products"):
                prefixes = {f.vuln_id_from_tool.split(".")[1] for f in findings}
                self.assertIn("AAD", prefixes)

            with self.subTest("every control id is unique"):
                self.assertEqual(14, len({f.vuln_id_from_tool for f in findings}))

    def test_severity_mapping(self):
        parser = ScubaGearParser()
        self.assertEqual("High", parser._severity("Fail", "Shall"))
        self.assertEqual("Medium", parser._severity("Fail", "Should"))
        self.assertEqual("Low", parser._severity("Warning", "Should"))
        self.assertIsNone(parser._severity("Pass", "Shall"))
        self.assertIsNone(parser._severity("N/A", "Shall/Not-Implemented"))
