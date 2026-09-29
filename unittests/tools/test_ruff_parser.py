from dojo.models import Test
from dojo.tools.ruff.parser import RuffParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestRuffParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("ruff") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = RuffParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        """An S-code is flake8-bandit, so it carries security weight."""
        with (get_unit_tests_scans_path("ruff") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = RuffParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("S602", finding.vuln_id_from_tool)
            self.assertEqual("src/app.py", finding.file_path)
            self.assertEqual(3, finding.line)
            self.assertIn("shell=True", finding.title)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_security_rules_outrank_style(self):
        with (get_unit_tests_scans_path("ruff") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = RuffParser().get_findings(testfile, Test())
            self.assertEqual(7, len(findings))

            with self.subTest("the three S-codes are Medium, the rest Low"):
                medium = [f for f in findings if f.severity == "Medium"]
                self.assertEqual(3, len(medium))
                self.assertEqual(
                    {"S602", "S324", "S105"},
                    {f.vuln_id_from_tool for f in medium},
                )
                self.assertEqual(4, len([f for f in findings if f.severity == "Low"]))

            with self.subTest("every finding names its rule and file"):
                for finding in findings:
                    self.assertTrue(finding.vuln_id_from_tool)
                    self.assertEqual("src/app.py", finding.file_path)

    def test_severity_split(self):
        parser = RuffParser()
        self.assertEqual("Medium", parser._severity("S105"))
        self.assertEqual("Low", parser._severity("E401"))
        self.assertEqual("Low", parser._severity("F841"))
        self.assertEqual("Low", parser._severity(None))
