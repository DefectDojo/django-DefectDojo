import io
import json

from dojo.models import Finding, Test
from dojo.tools.cfn_nag.parser import CfnNagParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path, skip_unless_v3


class TestCfnNagParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("cfn_nag") / filename).open(encoding="utf-8") as file:
            return list(CfnNagParser().get_findings(file, Test()))

    def report(self, filename):
        with (get_unit_tests_scans_path("cfn_nag") / filename).open(encoding="utf-8") as file:
            return json.load(file)

    def test_scan_type_metadata(self):
        parser = CfnNagParser()
        self.assertEqual(["cfn-nag Scan"], parser.get_scan_types())
        self.assertEqual("cfn-nag Scan", parser.get_label_for_scan_types("cfn-nag Scan"))
        self.assertIn("cfn_nag_scan", parser.get_description_for_scan_types("cfn-nag Scan"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("cfn_nag_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("cfn_nag_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `cfn_nag_scan --output-format json` run."""
        findings = self.parse("cfn_nag_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("SQS Queue should specify KmsMasterKeyId property", finding.title)
        self.assertEqual("W48", finding.vuln_id_from_tool)
        self.assertEqual("Medium", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("single.yaml", finding.file_path)
        self.assertEqual(5, finding.line)
        self.assertEqual("ApplicationQueue", finding.component_name)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

        self.assertIn("**Resource:** ApplicationQueue", finding.description)
        self.assertIn("**Rule ID:** W48", finding.description)
        self.assertIn("**Result:** WARN", finding.description)

    def test_leading_dot_slash_is_dropped_from_the_path(self):
        """
        cfn-nag echoes the path it was given, so a relative scan reports "./single.yaml".

        The leading "./" is dropped so the path reads normally; nothing else is rewritten.
        """
        report = self.report("cfn_nag_one_vuln.json")
        self.assertEqual("./single.yaml", report[0]["filename"])
        self.assertEqual("single.yaml", self.parse("cfn_nag_one_vuln.json")[0].file_path)

    def test_many_vuln_is_one_finding_per_resource(self):
        """
        One cfn-nag violation can cover several resources, and each becomes its own finding.

        The unencrypted-queue rule fires once for two queues, reporting parallel
        logical_resource_ids and line_numbers lists. Nine violations therefore yield ten findings -
        emitting one finding per violation would mean fixing one queue could not close it.
        """
        report = self.report("cfn_nag_many_vuln.json")
        violations = report[0]["file_results"]["violations"]
        self.assertEqual(9, len(violations))
        self.assertEqual(
            10, sum(len(v["logical_resource_ids"]) for v in violations),
        )

        findings = self.parse("cfn_nag_many_vuln.json")
        self.assertEqual(10, len(findings))

    def test_the_shared_violation_pairs_resources_with_lines_by_index(self):
        """The two lists are index-aligned, so each queue keeps its own line number."""
        findings = self.parse("cfn_nag_many_vuln.json")
        queues = [f for f in findings if f.vuln_id_from_tool == "W48"]
        self.assertEqual(2, len(queues))
        self.assertEqual(
            [("ApplicationQueue", 36), ("SecondQueue", 40)],
            sorted((f.component_name, f.line) for f in queues),
        )

    def test_siblings_are_named_in_the_description(self):
        """A reader should know other findings exist for the same rule."""
        findings = self.parse("cfn_nag_many_vuln.json")
        first = next(f for f in findings if f.component_name == "ApplicationQueue")
        self.assertIn("**Also reported for:** SecondQueue", first.description)

        # A violation covering a single resource says nothing about siblings.
        single = self.parse("cfn_nag_one_vuln.json")[0]
        self.assertNotIn("**Also reported for:**", single.description)

    def test_fail_and_warn_map_to_different_severities(self):
        """
        A FAIL is a rule the template breaks; a WARN may or may not be a problem depending on
        intent, so the two are not flattened together.
        """
        findings = self.parse("cfn_nag_many_vuln.json")
        by_rule = {f.vuln_id_from_tool: f.severity for f in findings}
        self.assertEqual("High", by_rule["F38"])
        self.assertEqual("High", by_rule["F3"])
        self.assertEqual("Medium", by_rule["W11"])
        self.assertEqual({"High", "Medium"}, set(by_rule.values()))

    def test_many_vuln_rules(self):
        findings = self.parse("cfn_nag_many_vuln.json")
        self.assertEqual(
            ["F3", "F38", "W11", "W2", "W36", "W40", "W48", "W48", "W5", "W9"],
            sorted(f.vuln_id_from_tool for f in findings),
        )
        for finding in findings:
            self.assertEqual("many.yaml", finding.file_path)

    def test_violation_without_a_resource(self):
        """A violation that names no resource is still reported, anchored to its first line."""
        report = io.StringIO(json.dumps([{
            "filename": "t.yaml",
            "file_results": {"violations": [{
                "id": "W1", "type": "WARN", "message": "template-wide problem",
                "logical_resource_ids": [], "line_numbers": [12],
            }]},
        }]))
        findings = list(CfnNagParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual(12, findings[0].line)
        self.assertIsNone(findings[0].component_name)

    def test_short_line_list_falls_back(self):
        """A resource list longer than the line list still produces a finding per resource."""
        report = io.StringIO(json.dumps([{
            "filename": "t.yaml",
            "file_results": {"violations": [{
                "id": "W1", "type": "WARN", "message": "m",
                "logical_resource_ids": ["A", "B"], "line_numbers": [7],
            }]},
        }]))
        findings = list(CfnNagParser().get_findings(report, Test()))
        self.assertEqual(2, len(findings))
        self.assertEqual([7, 7], [f.line for f in findings])

    def test_severity_map(self):
        parser = CfnNagParser()
        for kind, expected in [("FAIL", "High"), ("WARN", "Medium")]:
            report = io.StringIO(json.dumps([{
                "filename": "t.yaml",
                "file_results": {"violations": [{"id": "X", "type": kind, "message": "m"}]},
            }]))
            self.assertEqual(expected, list(parser.get_findings(report, Test()))[0].severity)

        report = io.StringIO(json.dumps([{
            "filename": "t.yaml",
            "file_results": {"violations": [{"id": "X", "type": "NEW", "message": "m"}]},
        }]))
        self.assertEqual("Medium", list(parser.get_findings(report, Test()))[0].severity)

    def test_empty_report(self):
        self.assertEqual([], list(CfnNagParser().get_findings(io.StringIO("[]"), Test())))

    def test_wrong_shape_is_rejected(self):
        with self.assertRaises(TypeError):
            list(CfnNagParser().get_findings(io.StringIO('{"violations": []}'), Test()))
        with self.assertRaises(TypeError):
            list(CfnNagParser().get_findings(io.StringIO("[4]"), Test()))

    @skip_unless_v3
    def test_locations(self):
        findings = self.parse("cfn_nag_one_vuln.json")
        locations = findings[0].unsaved_locations
        self.assertEqual(1, len(locations))
        self.assertEqual("code", locations[0].type)
        self.assertEqual("single.yaml", locations[0].data["file_path"])
        self.assertEqual(5, locations[0].data["line"])
