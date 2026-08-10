from dojo.models import Test
from dojo.tools.slither.parser import SlitherParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSlitherParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("slither") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = SlitherParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("slither") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = SlitherParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("High", finding.severity)
            self.assertEqual("reentrancy-eth", finding.vuln_id_from_tool)
            self.assertEqual("sol/Example.sol", finding.file_path)
            self.assertEqual(14, finding.line)
            self.assertTrue(finding.title.startswith("reentrancy-eth: "))
            self.assertIn("**Impact:** High", finding.description)
            self.assertIn("**Confidence:** Medium", finding.description)
            self.assertIn("Detector-Documentation", finding.references)
            self.assertTrue(finding.unique_id_from_tool)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("slither") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = SlitherParser().get_findings(testfile, Test())
            self.assertEqual(5, len(findings))

            with self.subTest("impact is the severity axis, not confidence"):
                self.assertEqual(2, len([f for f in findings if f.severity == "High"]))
                self.assertEqual(1, len([f for f in findings if f.severity == "Low"]))
                # Slither's Informational impact carries no security weight.
                self.assertEqual(2, len([f for f in findings if f.severity == "Info"]))

            with self.subTest("detector names are preserved"):
                checks = {f.vuln_id_from_tool for f in findings}
                self.assertIn("reentrancy-eth", checks)

            with self.subTest("every finding is anchored in the contract source"):
                for finding in findings:
                    self.assertEqual("sol/Example.sol", finding.file_path)
                    self.assertIsNotNone(finding.line)

            with self.subTest("each detector result keeps its own stable id"):
                self.assertEqual(5, len({f.unique_id_from_tool for f in findings}))

    def test_title_uses_the_first_line_of_a_multiline_description(self):
        parser = SlitherParser()
        detector = {"check": "x", "description": "First line.\n\tSecond line.\n"}
        self.assertEqual("First line.", parser._summary(detector))
        self.assertEqual("x", parser._summary({"check": "x", "description": ""}))
