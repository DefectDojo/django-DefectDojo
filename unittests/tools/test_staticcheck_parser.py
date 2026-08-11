from dojo.models import Test
from dojo.tools.staticcheck.parser import StaticcheckParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestStaticcheckParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("staticcheck") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = StaticcheckParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("staticcheck") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = StaticcheckParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("S1002", finding.vuln_id_from_tool)
            self.assertEqual("Info", finding.severity)
            self.assertEqual("main.go", finding.file_path)
            self.assertEqual(15, finding.line)
            self.assertIn("should omit comparison to bool constant", finding.title)
            self.assertIn("**Check:** S1002", finding.description)
            self.assertIn("**Column:** 9", finding.description)
            self.assertIn("**Ends at:** 15:41", finding.description)
            self.assertTrue(finding.active)
            self.assertFalse(finding.false_p)
            self.assertTrue(finding.static_finding)

    def test_parse_many_findings(self):
        """The check code prefix decides severity, so gosimple and staticcheck do not collapse."""
        with (get_unit_tests_scans_path("staticcheck") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = StaticcheckParser().get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

            with self.subTest("SA checks are bugs, S1 checks are simplifications"):
                self.assertEqual(
                    {"S1002": "Info", "SA4014": "Medium", "SA9003": "Medium"},
                    {f.vuln_id_from_tool: f.severity for f in findings},
                )

            with self.subTest("every finding is located in the analysed package"):
                for finding in findings:
                    self.assertEqual("main.go", finding.file_path)
                    self.assertIsNotNone(finding.line)
                    self.assertTrue(finding.title.startswith(finding.vuln_id_from_tool))

    def test_severity_by_prefix_covers_every_analyser(self):
        """Staticcheck's four analysers plus unused must each map to a real severity."""
        parser = StaticcheckParser()
        self.assertEqual("Medium", parser._severity_for("SA1000", "error"))
        self.assertEqual("Info", parser._severity_for("S1000", "error"))
        self.assertEqual("Info", parser._severity_for("ST1000", "error"))
        self.assertEqual("Info", parser._severity_for("QF1001", "error"))
        self.assertEqual("Low", parser._severity_for("U1000", "error"))

        with self.subTest("an unrecognised code still gets a severity"):
            self.assertEqual("Low", parser._severity_for("XX9999", "error"))

        with self.subTest("a lint:ignore directive downgrades rather than drops"):
            self.assertEqual("Info", parser._severity_for("SA1000", "ignored"))

    def test_compile_error_is_reported_as_a_blind_scan(self):
        """A compile record means the package never got analysed, which matters more than a lint hit."""
        parser = StaticcheckParser()
        finding = parser._to_finding(
            {
                "code": "compile",
                "severity": "error",
                "location": {"file": "", "line": 0, "column": 0},
                "end": {"file": "", "line": 0, "column": 0},
                "message": "# example.test/sample\n./main.go:9:2: declared and not used: x",
            },
            Test(),
        )
        self.assertEqual("High", finding.severity)
        self.assertEqual("compile", finding.vuln_id_from_tool)
