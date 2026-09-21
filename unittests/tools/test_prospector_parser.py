from dojo.models import Test
from dojo.tools.prospector.parser import ProspectorParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestProspectorParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("prospector") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = ProspectorParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        """A dodgy message is a security source, so it carries weight."""
        with (get_unit_tests_scans_path("prospector") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = ProspectorParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("High", finding.severity)
            self.assertEqual("aws_secret_key", finding.vuln_id_from_tool)
            self.assertEqual("app.py", finding.file_path)
            self.assertEqual(2, finding.line)
            self.assertIn("**Tool:** dodgy", finding.description)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_security_sources_outrank_style(self):
        with (get_unit_tests_scans_path("prospector") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = ProspectorParser().get_findings(testfile, Test())
            self.assertEqual(5, len(findings))

            with self.subTest("dodgy findings are High, linter noise is Low"):
                high = [f for f in findings if f.severity == "High"]
                low = [f for f in findings if f.severity == "Low"]
                self.assertEqual(2, len(high))
                self.assertEqual(3, len(low))
                for finding in high:
                    self.assertIn("**Tool:** dodgy", finding.description)

            with self.subTest("the aggregated tools are all represented"):
                tools = {line for f in findings for line in f.description.split("\n") if line.startswith("**Tool:**")}
                self.assertEqual(
                    {"**Tool:** dodgy", "**Tool:** pylint", "**Tool:** pyflakes"},
                    tools,
                )
