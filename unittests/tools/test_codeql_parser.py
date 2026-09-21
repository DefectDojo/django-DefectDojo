from dojo.models import Test
from dojo.tools.codeql.parser import CodeQLParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestCodeQLParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("codeql") / "no_findings.sarif").open(encoding="utf-8") as testfile:
            findings = CodeQLParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("codeql") / "one_finding.sarif").open(encoding="utf-8") as testfile:
            findings = CodeQLParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("py/sql-injection: SQL query built from user-controlled sources", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(89, finding.cwe)
            self.assertEqual("py/sql-injection", finding.vuln_id_from_tool)
            self.assertEqual("app/web.py", finding.file_path)
            self.assertEqual(16, finding.line)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)
            self.assertFalse(finding.false_p)

            with self.subTest("the query's own confidence and score are recorded"):
                self.assertIn("**Query precision:** high", finding.description)
                self.assertIn("**Problem kind:** path-problem", finding.description)
                self.assertIn("**CodeQL security severity:** 8.8", finding.description)

            with self.subTest("the taint path is preserved"):
                self.assertIn("Code flow", finding.description)
                self.assertIn("app/web.py:L16", finding.description)

            with self.subTest("SARIF fingerprints become the tool's unique id"):
                self.assertIn("primaryLocationLineHash", finding.unique_id_from_tool)

    def test_parse_many_findings(self):
        """security-severity drives severity, so the three queries do not all land the same."""
        with (get_unit_tests_scans_path("codeql") / "many_findings.sarif").open(encoding="utf-8") as testfile:
            findings = CodeQLParser().get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

            with self.subTest("severity follows CodeQL's CVSS-style score"):
                by_rule = {f.vuln_id_from_tool: f.severity for f in findings}
                self.assertEqual(
                    {
                        "py/command-line-injection": "Critical",
                        "py/sql-injection": "High",
                        "py/path-injection": "High",
                    },
                    by_rule,
                )

            with self.subTest("CWEs come from the rules' cwe tags"):
                self.assertEqual(
                    {"py/sql-injection": 89, "py/path-injection": 99, "py/command-line-injection": 88},
                    {f.vuln_id_from_tool: f.cwe for f in findings},
                )

            with self.subTest("every finding is located in the scanned source"):
                for finding in findings:
                    self.assertEqual("app/web.py", finding.file_path)
                    self.assertIsNotNone(finding.line)
                    self.assertTrue(finding.title.startswith(finding.vuln_id_from_tool))
