from dojo.models import Test
from dojo.tools.phpstan.parser import PHPStanParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestPHPStanParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("phpstan") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = PHPStanParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("phpstan") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = PHPStanParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("return.missing", finding.vuln_id_from_tool)
            self.assertEqual("src/Report.php", finding.file_path)
            self.assertEqual(18, finding.line)
            self.assertIn("return statement is missing", finding.title)
            self.assertIn("**Identifier:** return.missing", finding.description)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

            with self.subTest("a diagnostic PHPStan will not let you ignore is not the lowest rung"):
                self.assertEqual("Medium", finding.severity)
                self.assertIn("**Ignorable:** False", finding.description)

    def test_parse_many_findings(self):
        """Diagnostics are grouped under a files map, so every file's messages must be walked."""
        with (get_unit_tests_scans_path("phpstan") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = PHPStanParser().get_findings(testfile, Test())
            self.assertEqual(6, len(findings))

            with self.subTest("findings are attributed to the file they came from"):
                self.assertEqual(
                    {"src/Handler.php": 2, "src/Report.php": 4},
                    {
                        path: len([f for f in findings if f.file_path == path])
                        for path in {f.file_path for f in findings}
                    },
                )

            with self.subTest("ignorable is Low and non-ignorable is Medium"):
                self.assertEqual(1, len([f for f in findings if f.severity == "Medium"]))
                self.assertEqual(5, len([f for f in findings if f.severity == "Low"]))
                self.assertEqual(
                    "return.missing",
                    next(f.vuln_id_from_tool for f in findings if f.severity == "Medium"),
                )

            with self.subTest("the same identifier in two files stays separate"):
                repeated = [f for f in findings if f.vuln_id_from_tool == "missingType.iterableValue"]
                self.assertEqual(2, len(repeated))
                self.assertEqual({"src/Handler.php", "src/Report.php"}, {f.file_path for f in repeated})

            with self.subTest("PHPStan's tip is carried through when it offers one"):
                tipped = [f for f in findings if "**Tip:**" in f.description]
                self.assertEqual(2, len(tipped))

    def test_analysis_errors_are_imported_separately(self):
        """Top level errors mean part of the codebase was never analysed."""
        parser = PHPStanParser()
        finding = parser._analysis_finding("Configuration file not found.", Test())
        self.assertEqual("High", finding.severity)
        self.assertIn("Configuration file not found.", finding.title)
        self.assertIsNone(finding.file_path)
        self.assertIn("may not have been analysed", finding.description)
