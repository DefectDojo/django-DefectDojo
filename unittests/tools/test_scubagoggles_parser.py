from dojo.models import Test
from dojo.tools.scubagoggles.parser import ScubaGogglesParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestScubaGogglesParser(DojoTestCase):

    def test_parse_no_findings(self):
        """Pass, N/A and 'No events found' controls are not findings."""
        with (get_unit_tests_scans_path("scubagoggles") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = ScubaGogglesParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("scubagoggles") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = ScubaGogglesParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("GWS.CALENDAR.2.1v1", finding.vuln_id_from_tool)
            self.assertEqual("High", finding.severity)
            self.assertEqual("calendar", finding.component_name)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

            with self.subTest("the requirement markup is stripped from the title"):
                self.assertTrue(finding.title.startswith("GWS.CALENDAR.2.1v1: "))
                self.assertNotIn("<", finding.title)
                self.assertNotIn("indicator-badge", finding.title)

            with self.subTest("result, criticality and details reach the description"):
                self.assertIn("**Result:** Fail", finding.description)
                self.assertIn("**Criticality:** Shall", finding.description)
                self.assertIn("**Product:** calendar", finding.description)
                self.assertIn("**Tenant:** Cool Example Org", finding.description)
                self.assertNotIn("<", finding.description)

            with self.subTest("the baseline group url becomes the reference"):
                self.assertIn("baselines", finding.references)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("scubagoggles") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = ScubaGogglesParser().get_findings(testfile, Test())
            self.assertEqual(14, len(findings))

            with self.subTest("a failed Shall is High, a Warning is Low"):
                self.assertEqual(8, len([f for f in findings if f.severity == "High"]))
                self.assertEqual(6, len([f for f in findings if f.severity == "Low"]))

            with self.subTest("findings span several Workspace products"):
                self.assertEqual({"calendar", "chat", "drive"}, {f.component_name for f in findings})

            with self.subTest("every finding carries a baseline control id"):
                for finding in findings:
                    self.assertTrue(finding.vuln_id_from_tool.startswith("GWS."))

    def test_not_implemented_baselines_are_skipped(self):
        """A baseline ScubaGoggles cannot evaluate is a gap in the tool, not the tenant."""
        parser = ScubaGogglesParser()
        self.assertIsNone(parser._severity("N/A", "Shall/Not-Implemented"))
        self.assertIsNone(parser._severity("N/A", "Should/Not-Implemented"))
        self.assertIsNone(parser._severity("Pass", "Shall"))
        self.assertIsNone(parser._severity("No events found", "Should"))
        self.assertEqual("High", parser._severity("Fail", "Shall"))
        self.assertEqual("Medium", parser._severity("Fail", "Should"))
        self.assertEqual("Low", parser._severity("Warning", "Should"))
