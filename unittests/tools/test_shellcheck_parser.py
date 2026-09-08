from dojo.models import Test
from dojo.tools.shellcheck.parser import ShellcheckParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestShellcheckParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("shellcheck") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = ShellcheckParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("shellcheck") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = ShellcheckParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("SC2086", finding.vuln_id_from_tool)
            self.assertEqual("Low", finding.severity)
            self.assertEqual("scripts/deploy.sh", finding.file_path)
            self.assertEqual(5, finding.line)
            self.assertIn("Double quote to prevent globbing and word splitting.", finding.title)
            self.assertEqual("https://www.shellcheck.net/wiki/SC2086", finding.references)
            self.assertTrue(finding.fix_available)
            self.assertIn("**Fix available:**", finding.description)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("shellcheck") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = ShellcheckParser().get_findings(testfile, Test())
            self.assertEqual(4, len(findings))

            with self.subTest("warning outranks info"):
                self.assertEqual(1, len([f for f in findings if f.severity == "Medium"]))
                self.assertEqual(3, len([f for f in findings if f.severity == "Low"]))

            with self.subTest("the destructive-rm check is present"):
                # SC2115 guards against `rm -rf $VAR/*` expanding to /*.
                warning = next(f for f in findings if f.severity == "Medium")
                self.assertEqual("SC2115", warning.vuln_id_from_tool)

            with self.subTest("the numeric code is rendered in ShellCheck's documented form"):
                for finding in findings:
                    self.assertRegex(finding.vuln_id_from_tool, r"^SC\d+$")
                    self.assertEqual("scripts/deploy.sh", finding.file_path)

    def test_severity_scale(self):
        parser = ShellcheckParser()
        self.assertEqual("High", parser.SEVERITY["error"])
        self.assertEqual("Medium", parser.SEVERITY["warning"])
        self.assertEqual("Low", parser.SEVERITY["info"])
        self.assertEqual("Info", parser.SEVERITY["style"])
