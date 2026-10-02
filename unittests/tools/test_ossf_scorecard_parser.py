from dojo.models import Test
from dojo.tools.ossf_scorecard.parser import OSSFScorecardParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestOSSFScorecardParser(DojoTestCase):

    def test_parse_no_findings(self):
        """A fully passing check, and one that could not conclude, are both skipped."""
        with (get_unit_tests_scans_path("ossf_scorecard") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = OSSFScorecardParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("ossf_scorecard") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = OSSFScorecardParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Vulnerabilities: scored 0 of 10", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("Vulnerabilities", finding.vuln_id_from_tool)
            self.assertEqual("github.com/ossf/scorecard", finding.component_name)
            self.assertIn("**Score:** 0 of 10", finding.description)
            self.assertIn("**Aggregate score:** 9", finding.description)
            self.assertIn("**Scorecard version:** v5.5.0", finding.description)
            self.assertIn("docs/checks.md", finding.references)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("ossf_scorecard") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = OSSFScorecardParser().get_findings(testfile, Test())
            self.assertEqual(4, len(findings))

            with self.subTest("severity tracks how far the check falls short"):
                by_check = {f.vuln_id_from_tool: f for f in findings}
                self.assertEqual("High", by_check["Vulnerabilities"].severity)
                self.assertEqual("Medium", by_check["CII-Best-Practices"].severity)
                self.assertEqual("Low", by_check["Token-Permissions"].severity)
                self.assertEqual("Low", by_check["Pinned-Dependencies"].severity)

            with self.subTest("an inconclusive check never becomes a finding"):
                self.assertNotIn("Branch-Protection", {f.vuln_id_from_tool for f in findings})

            with self.subTest("each check keeps its documentation link"):
                for finding in findings:
                    self.assertIn("https://", finding.references)

    def test_score_bands(self):
        parser = OSSFScorecardParser()
        self.assertEqual("High", parser._severity(0))
        self.assertEqual("High", parser._severity(3))
        self.assertEqual("Medium", parser._severity(4))
        self.assertEqual("Medium", parser._severity(6))
        self.assertEqual("Low", parser._severity(7))
        self.assertEqual("Low", parser._severity(9))
