import io
import json

from dojo.models import Finding, Test
from dojo.tools.golangci_lint.parser import GolangciLintParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestGolangciLintParser(DojoTestCase):
    def scan(self, filename):
        return get_unit_tests_scans_path("golangci_lint") / filename

    def parse(self, filename):
        with self.scan(filename).open(encoding="utf-8") as file:
            return list(GolangciLintParser().get_findings(file, Test()))

    def by_rule(self, filename):
        return {f.vuln_id_from_tool: f for f in self.parse(filename)}

    def test_scan_type_metadata(self):
        parser = GolangciLintParser()
        self.assertEqual(["golangci-lint Scan"], parser.get_scan_types())
        self.assertEqual("golangci-lint Scan", parser.get_label_for_scan_types("golangci-lint Scan"))
        self.assertIn("gosec", parser.get_description_for_scan_types("golangci-lint Scan"))

    def test_no_vuln(self):
        """A clean run really does emit "Issues": [] plus a Report block."""
        self.assertEqual(0, len(self.parse("golangci_lint_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("golangci_lint_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        findings = self.parse("golangci_lint_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("G402: TLS InsecureSkipVerify set true.", finding.title)
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("G402", finding.vuln_id_from_tool)
        self.assertEqual("main.go", finding.file_path)
        self.assertEqual(30, finding.line)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

        self.assertIn("**Linter:** gosec", finding.description)
        self.assertIn("**Rule:** G402", finding.description)
        self.assertIn("**Message:** TLS InsecureSkipVerify set true.", finding.description)
        # The offending line is carried through for triage, fenced as Go.
        self.assertIn("InsecureSkipVerify: true", finding.description)
        self.assertIn("```go", finding.description)

        self.assertEqual(["linter:gosec", "rule:G402"], finding.unsaved_tags)

    def test_many_vuln(self):
        findings = self.parse("golangci_lint_many_vuln.json")
        self.assertEqual(7, len(findings))
        self.assertEqual(
            ["G101", "G304", "G306", "G401", "G402", "G404", "G501"],
            sorted(f.vuln_id_from_tool for f in findings),
        )

    def test_only_the_security_linters_are_imported(self):
        """
        The point of this parser: golangci-lint is overwhelmingly a style and correctness linter.

        This fixture is a real `linters.default: all` run over the same file - 19 issues, of which
        only the 7 gosec ones are security findings. Importing the other 12 would bury real
        findings under lint opinions.
        """
        raw = json.loads(self.scan("golangci_lint_mixed_linters.json").read_text(encoding="utf-8"))
        linters = {i["FromLinter"] for i in raw["Issues"]}
        self.assertEqual(19, len(raw["Issues"]))
        self.assertTrue({"exhaustruct", "forbidigo", "nlreturn", "unused", "wrapcheck", "wsl"} <= linters)

        findings = self.parse("golangci_lint_mixed_linters.json")
        self.assertEqual(7, len(findings))
        for finding in findings:
            self.assertRegex(finding.vuln_id_from_tool, r"^G\d+$")
            self.assertEqual(["linter:gosec"], finding.unsaved_tags[:1])

    def test_severity_comes_from_the_tool_not_from_this_parser(self):
        """
        golangci-lint v2 passes gosec's own low/medium/high through in Severity.

        Verified against the raw fixture so a future change that starts inventing severities is
        caught. The style linters, by contrast, emit no severity at all - which is why the fallback
        below is unreachable for anything this parser imports.
        """
        raw = json.loads(self.scan("golangci_lint_mixed_linters.json").read_text(encoding="utf-8"))
        gosec_severities = {i["Severity"] for i in raw["Issues"] if i["FromLinter"] == "gosec"}
        other_severities = {i.get("Severity", "") for i in raw["Issues"] if i["FromLinter"] != "gosec"}
        self.assertEqual({"high", "medium"}, gosec_severities)
        self.assertEqual({""}, other_severities)

        findings = self.by_rule("golangci_lint_many_vuln.json")
        self.assertEqual("High", findings["G101"].severity)
        self.assertEqual("High", findings["G402"].severity)
        self.assertEqual("High", findings["G404"].severity)
        self.assertEqual("Medium", findings["G401"].severity)
        self.assertEqual("Medium", findings["G501"].severity)

    def test_a_configured_severity_vocabulary_is_mapped(self):
        """A golangci-lint `severity` block can rewrite gosec's values to error/warning/info."""
        parser = GolangciLintParser()
        for value, expected in [
            ("error", "High"), ("warning", "Medium"), ("info", "Info"),
            ("critical", "Critical"), ("low", "Low"), ("HIGH", "High"),
        ]:
            self.assertEqual(expected, parser.severity({"Severity": value}), value)

    def test_an_absent_severity_falls_back_to_medium_not_info(self):
        """
        Everything imported here is a security weakness, so Info would be wrong.

        DefectDojo treats Info as non-actionable; gosec's own default is medium, so that is the
        fallback for a report whose severities have been stripped by configuration.
        """
        parser = GolangciLintParser()
        self.assertEqual("Medium", parser.severity({}))
        self.assertEqual("Medium", parser.severity({"Severity": ""}))
        self.assertEqual("Medium", parser.severity({"Severity": "not-a-level"}))

    def test_a_linter_without_a_rule_id_is_still_imported(self):
        """The bidichk linter reports the Trojan Source class and emits no G-style rule id."""
        report = io.StringIO(json.dumps({"Issues": [{
            "FromLinter": "bidichk",
            "Text": "found dangerous unicode character sequence",
            "Severity": "error",
            "Pos": {"Filename": "config.go", "Line": 12},
        }]}))
        findings = list(GolangciLintParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("found dangerous unicode character sequence", findings[0].title)
        self.assertIsNone(findings[0].vuln_id_from_tool)
        self.assertEqual("High", findings[0].severity)
        # No rule id means no rule tag, only the linter tag.
        self.assertEqual(["linter:bidichk"], findings[0].unsaved_tags)

    def test_a_null_issues_list_is_accepted(self):
        report = io.StringIO(json.dumps({"Issues": None, "Report": {}}))
        self.assertEqual(0, len(list(GolangciLintParser().get_findings(report, Test()))))

    def test_an_unexpected_shape_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(GolangciLintParser().get_findings(io.StringIO("[]"), Test()))
        self.assertIn("Issues", str(raised.exception))

    def test_the_scanned_sample_is_committed_as_txt(self):
        """
        A .go fixture would be compiled or vetted as part of the repo; .txt is inert.

        The sample also deliberately contains no provider-shaped credential - the G101 case uses a
        plain high-entropy hex string, so nothing here can trip a secret scanner.
        """
        sample = self.scan("sample_insecure_source.txt")
        self.assertTrue(sample.is_file())
        text = sample.read_text(encoding="utf-8")
        self.assertIn("InsecureSkipVerify", text)
        self.assertFalse(self.scan("sample_insecure_source.go").exists())
        for shape in ("AKIA", "ghp_", "AIza", "xoxb-"):
            self.assertNotIn(shape, text)
