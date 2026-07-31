import io
import json

from dojo.models import Finding, Test
from dojo.tools.infer.parser import InferParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path, skip_unless_v3


class TestInferParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("infer") / filename).open(encoding="utf-8") as file:
            return list(InferParser().get_findings(file, Test()))

    def report(self, filename):
        with (get_unit_tests_scans_path("infer") / filename).open(encoding="utf-8") as file:
            return json.load(file)

    def test_scan_type_metadata(self):
        parser = InferParser()
        self.assertEqual(["Infer Scan"], parser.get_scan_types())
        self.assertEqual("Infer Scan", parser.get_label_for_scan_types("Infer Scan"))
        self.assertIn("infer run", parser.get_description_for_scan_types("Infer Scan"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("infer_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("infer_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `infer run -- gcc -c deref.c`."""
        findings = self.parse("infer_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Null Dereference", finding.title)
        self.assertEqual("NULLPTR_DEREFERENCE", finding.vuln_id_from_tool)
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("deref.c", finding.file_path)
        self.assertEqual(5, finding.line)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

        self.assertIn("could be null", finding.description)
        self.assertIn("**Category:** Null pointer dereference", finding.description)
        self.assertIn("**Procedure:** main (starts at line 3)", finding.description)
        self.assertIn("**Column:** 5", finding.description)

    def test_one_vuln_trace(self):
        """
        The trace is Infer's explanation of how the issue is reached, and is worth keeping.

        Without it a null dereference says only that a pointer might be null, not where the null
        came from.
        """
        finding = self.parse("infer_one_vuln.json")[0]
        self.assertIn("**Trace:**", finding.description)
        self.assertIn("deref.c:4", finding.description)
        self.assertIn("invalid access occurs here", finding.description)

    def test_many_vuln(self):
        findings = self.parse("infer_many_vuln.json")
        self.assertEqual(9, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertEqual("defects.c", finding.file_path)
            self.assertTrue(finding.static_finding)

    def test_many_vuln_issue_types(self):
        findings = self.parse("infer_many_vuln.json")
        self.assertEqual(
            {
                "MEMORY_LEAK_C",
                "NULLPTR_DEREFERENCE",
                "PULSE_UNINITIALIZED_VALUE",
                "USE_AFTER_FREE",
            },
            {finding.vuln_id_from_tool for finding in findings},
        )
        titles = {f.vuln_id_from_tool: f.title for f in findings}
        self.assertEqual("Memory Leak", titles["MEMORY_LEAK_C"])
        self.assertEqual("Use After Free", titles["USE_AFTER_FREE"])
        self.assertEqual("Uninitialized Value", titles["PULSE_UNINITIALIZED_VALUE"])

    def test_infer_hash_is_not_unique_and_is_not_the_key(self):
        """
        Infer's own hash identifies the bug site, not the individual issue.

        The many_vuln report holds nine issues but only eight distinct hashes: two null
        dereferences at the same line, reached from two different null origins, share one. Keying
        findings on that hash would silently discard one of two real results, so it is recorded in
        the description for traceability and nothing more.
        """
        report = self.report("infer_many_vuln.json")
        self.assertEqual(9, len(report))
        self.assertEqual(8, len({issue["hash"] for issue in report}))

        findings = self.parse("infer_many_vuln.json")
        self.assertEqual(9, len(findings), "a colliding hash must not collapse two issues")
        for finding in findings:
            self.assertIsNone(getattr(finding, "unique_id_from_tool", None))

    def test_colliding_issues_stay_distinguishable(self):
        """
        The two issues sharing a hash differ only in their qualifier and trace.

        Both are in the description, so the findings still have different hash_codes and both
        survive deduplication.
        """
        findings = self.parse("infer_many_vuln.json")
        at_line_15 = [
            f for f in findings
            if f.line == 15 and f.vuln_id_from_tool == "NULLPTR_DEREFERENCE"
        ]
        self.assertEqual(2, len(at_line_15))
        self.assertEqual(2, len({finding.description for finding in at_line_15}))
        origins = sorted("originating from line 11" in f.description for f in at_line_15)
        self.assertEqual([False, True], origins)

    def test_severity_map(self):
        """Infer's four reporting levels each map to a distinct DefectDojo severity."""
        parser = InferParser()
        for level, expected in [
            ("ERROR", "High"),
            ("WARNING", "Medium"),
            ("INFO", "Low"),
            ("ADVICE", "Info"),
        ]:
            report = io.StringIO(json.dumps([{
                "bug_type": "X", "bug_type_hum": "X", "severity": level,
                "file": "a.c", "line": 1,
            }]))
            self.assertEqual(expected, list(parser.get_findings(report, Test()))[0].severity)

        # An unrecognised level is reported rather than dropped.
        report = io.StringIO(json.dumps([{"bug_type": "X", "severity": "NEW", "file": "a.c", "line": 1}]))
        self.assertEqual("Medium", list(parser.get_findings(report, Test()))[0].severity)

    def test_issue_without_a_human_name_falls_back(self):
        report = io.StringIO(json.dumps([{"bug_type": "SOME_CHECK", "severity": "ERROR"}]))
        finding = list(InferParser().get_findings(report, Test()))[0]
        self.assertEqual("SOME_CHECK", finding.title)
        self.assertEqual("SOME_CHECK", finding.vuln_id_from_tool)

    def test_no_cwe(self):
        """Infer reports no CWE, so findings carry none rather than a guessed value."""
        for finding in self.parse("infer_many_vuln.json"):
            self.assertIsNone(finding.cwe)

    def test_empty_report(self):
        self.assertEqual([], list(InferParser().get_findings(io.StringIO("[]"), Test())))

    def test_wrong_shape_is_rejected(self):
        with self.assertRaises(TypeError):
            list(InferParser().get_findings(io.StringIO('{"issues": []}'), Test()))
        with self.assertRaises(TypeError):
            list(InferParser().get_findings(io.StringIO("[3]"), Test()))

    @skip_unless_v3
    def test_locations(self):
        findings = self.parse("infer_one_vuln.json")
        locations = findings[0].unsaved_locations
        self.assertEqual(1, len(locations))
        self.assertEqual("code", locations[0].type)
        self.assertEqual("deref.c", locations[0].data["file_path"])
        self.assertEqual(5, locations[0].data["line"])
