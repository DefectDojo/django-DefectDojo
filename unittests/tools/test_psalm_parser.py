from dojo.models import Test
from dojo.tools.psalm.parser import PsalmParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestPsalmParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("psalm") / "no_findings.sarif").open(encoding="utf-8") as testfile:
            findings = PsalmParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("psalm") / "one_finding.sarif").open(encoding="utf-8") as testfile:
            findings = PsalmParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("TypeDoesNotContainType: string cannot be identical to int", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("src/Handler.php", finding.file_path)
            self.assertEqual(32, finding.line)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

            with self.subTest("the issue type, not the numeric shortcode, identifies the finding"):
                self.assertEqual("TypeDoesNotContainType", finding.vuln_id_from_tool)
                self.assertIn("**Psalm shortcode:** 56", finding.description)

            with self.subTest("Psalm reports no CWE, so cwe stays unset"):
                self.assertEqual(0, finding.cwe)

    def test_parse_many_findings(self):
        """Psalm's two issue levels arrive as SARIF error and note, and must not collapse."""
        with (get_unit_tests_scans_path("psalm") / "many_findings.sarif").open(encoding="utf-8") as testfile:
            findings = PsalmParser().get_findings(testfile, Test())
            self.assertEqual(9, len(findings))

            with self.subTest("error becomes High and note becomes Info"):
                self.assertEqual(4, len([f for f in findings if f.severity == "High"]))
                self.assertEqual(5, len([f for f in findings if f.severity == "Info"]))

            with self.subTest("every finding names its issue type and is located in the source"):
                for finding in findings:
                    self.assertTrue(finding.vuln_id_from_tool)
                    self.assertTrue(finding.title.startswith(finding.vuln_id_from_tool))
                    self.assertEqual("src/Handler.php", finding.file_path)
                    self.assertIsNotNone(finding.line)

            with self.subTest("the same issue type on different lines stays separate"):
                mixed = [f for f in findings if f.vuln_id_from_tool == "MixedAssignment"]
                self.assertEqual(2, len(mixed))
                self.assertEqual({18, 19}, {f.line for f in mixed})
