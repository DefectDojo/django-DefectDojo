import io
import json

from dojo.models import Finding, Test
from dojo.tools.cfn_lint.parser import CfnLintParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path, skip_unless_v3


class TestCfnLintParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("cfn_lint") / filename).open(encoding="utf-8") as file:
            return list(CfnLintParser().get_findings(file, Test()))

    def report(self, filename):
        with (get_unit_tests_scans_path("cfn_lint") / filename).open(encoding="utf-8") as file:
            return json.load(file)

    def test_scan_type_metadata(self):
        parser = CfnLintParser()
        self.assertEqual(["cfn-lint Scan"], parser.get_scan_types())
        self.assertEqual("cfn-lint Scan", parser.get_label_for_scan_types("cfn-lint Scan"))
        self.assertIn("cfn-lint --format json", parser.get_description_for_scan_types("cfn-lint Scan"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("cfn_lint_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("cfn_lint_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `cfn-lint --format json` run."""
        findings = self.parse("cfn_lint_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Check if Parameters are Used", finding.title)
        self.assertEqual("W2001", finding.vuln_id_from_tool)
        self.assertEqual("Medium", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("single.yaml", finding.file_path)
        self.assertEqual(7, finding.line)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

        self.assertIn("Parameter UnusedParameter not used.", finding.description)
        self.assertIn("**Rule ID:** W2001", finding.description)
        self.assertIn("**Location:** line 7, column 3", finding.description)
        self.assertIn("cfn-lint", finding.description)

    def test_title_is_the_rule_name_and_the_message_is_the_detail(self):
        """
        The rule's name is the title so instances of one rule group together.

        The message names the offending element and is the first line of the description, which is
        what tells a reader which parameter is unused.
        """
        finding = self.parse("cfn_lint_one_vuln.json")[0]
        self.assertEqual("Check if Parameters are Used", finding.title)
        self.assertTrue(finding.description.startswith("Parameter UnusedParameter not used."))

    def test_template_path_is_reported(self):
        """
        The template path locates the offending element, which a line number alone does not.

        A deeply nested resource property is much easier to find by path than by line.
        """
        findings = self.parse("cfn_lint_many_vuln.json")
        invalid_property = next(f for f in findings if f.vuln_id_from_tool == "E3002")
        self.assertIn(
            "**Template path:** Resources/ApplicationBucket/Properties/NotARealProperty",
            invalid_property.description,
        )

    def test_unique_id_from_tool_is_the_deterministic_match_id(self):
        """
        cfn-lint's per-match Id is deterministic and unique within a report, so it is used as the
        finding key.

        Running the same template twice produces the same Ids, which is what makes it a genuine
        finding identifier rather than a location hash - unlike, say, Infer's `hash`, which
        identifies a bug site and can repeat across distinct issues.
        """
        report = self.report("cfn_lint_many_vuln.json")
        ids = [match["Id"] for match in report]
        self.assertEqual(len(ids), len(set(ids)), "cfn-lint Ids are unique within a report")

        findings = self.parse("cfn_lint_many_vuln.json")
        self.assertEqual(sorted(ids), sorted(f.unique_id_from_tool for f in findings))

    def test_many_vuln(self):
        findings = self.parse("cfn_lint_many_vuln.json")
        self.assertEqual(5, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertEqual("many.yaml", finding.file_path)
            self.assertTrue(finding.static_finding)

    def test_many_vuln_rules_and_lines(self):
        findings = self.parse("cfn_lint_many_vuln.json")
        located = sorted((f.vuln_id_from_tool, f.line, f.severity) for f in findings)
        self.assertEqual(
            [
                ("E3002", 15, "High"),
                ("E6101", 24, "High"),
                ("W1020", 20, "Medium"),
                ("W2001", 4, "Medium"),
                ("W2001", 7, "Medium"),
            ],
            located,
        )

    def test_severity_reflects_cfn_lint_levels(self):
        """
        Error and Warning are template-correctness levels, not exploitability ratings.

        Both appear in the fixture, so a change that flattened them to one value fails here.
        """
        findings = self.parse("cfn_lint_many_vuln.json")
        self.assertEqual({"High", "Medium"}, {finding.severity for finding in findings})

    def test_severity_map(self):
        parser = CfnLintParser()
        for level, expected in [
            ("Fatal", "Critical"),
            ("Error", "High"),
            ("Warning", "Medium"),
            ("Informational", "Info"),
        ]:
            report = io.StringIO(json.dumps([{"Level": level, "Rule": {"Id": "X"}}]))
            self.assertEqual(expected, list(parser.get_findings(report, Test()))[0].severity)

        # An unrecognised level is reported rather than dropped.
        report = io.StringIO(json.dumps([{"Level": "Novel", "Rule": {"Id": "X"}}]))
        self.assertEqual("Medium", list(parser.get_findings(report, Test()))[0].severity)

    def test_match_without_a_rule(self):
        report = io.StringIO(json.dumps([{"Level": "Error", "Message": "something went wrong"}]))
        finding = list(CfnLintParser().get_findings(report, Test()))[0]
        self.assertEqual("cfn-lint match", finding.title)
        self.assertIsNone(finding.vuln_id_from_tool)
        self.assertIsNone(finding.line)

    def test_multiline_span_is_described(self):
        report = io.StringIO(json.dumps([{
            "Level": "Error",
            "Rule": {"Id": "E0001", "ShortDescription": "Broken"},
            "Location": {"Start": {"LineNumber": 3, "ColumnNumber": 1},
                         "End": {"LineNumber": 9, "ColumnNumber": 4}},
        }]))
        finding = list(CfnLintParser().get_findings(report, Test()))[0]
        self.assertIn("**Location:** line 3, column 1 to line 9", finding.description)

    def test_empty_report(self):
        self.assertEqual([], list(CfnLintParser().get_findings(io.StringIO("[]"), Test())))

    def test_wrong_shape_is_rejected(self):
        with self.assertRaises(TypeError):
            list(CfnLintParser().get_findings(io.StringIO('{"matches": []}'), Test()))
        with self.assertRaises(TypeError):
            list(CfnLintParser().get_findings(io.StringIO("[7]"), Test()))

    @skip_unless_v3
    def test_locations(self):
        findings = self.parse("cfn_lint_one_vuln.json")
        locations = findings[0].unsaved_locations
        self.assertEqual(1, len(locations))
        self.assertEqual("code", locations[0].type)
        self.assertEqual("single.yaml", locations[0].data["file_path"])
        self.assertEqual(7, locations[0].data["line"])
