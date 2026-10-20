import io
import json
from unittest.mock import patch

from dojo.models import Finding, Test
from dojo.tools.factory import get_parser
from dojo.tools.sarif_aggregated.parser import SarifAggregatedParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path

MULTI_LOCATION_FINGERPRINT = "codexSecurity:codex-security/v1:sha256:4e6b6d3623422b50a50ee192dfe76cb5a8d96d89c5b134b1023479ff4e0e5b25"
SINGLE_LOCATION_FINGERPRINT = "codexSecurity:codex-security/v1:sha256:5ae9571b7322589f3a04c194d2afa07571cfcfa850fd390ac9438a6c39a1cfba"
MULTI_LOCATION_COORDINATES = [
    ("src/src/main/java/com/example/stub/StubFile01.java", 61, 201),
    ("src/src/main/java/com/example/stub/StubFile02.java", 61, 202),
    ("src/src/main/java/com/example/stub/StubFile03.java", 56, 131),
    ("src/src/main/java/com/example/stub/StubFile04.java", 14, 24),
    ("src/src/main/java/com/example/stub/StubFile05.java", 14, 25),
    ("src/src/main/resources/StubFile06.xml", 24, 38),
]


class TestSarifAggregatedParser(DojoTestCase):
    def common_checks(self, finding):
        self.assertLessEqual(len(finding.title), 250)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        if finding.cwe:
            self.assertIsInstance(finding.cwe, int)
        self.assertEqual(True, finding.static_finding)
        self.assertEqual(False, finding.dynamic_finding)

    def parse_multi_location_report(self, *, locations):
        with (
            patch.dict("dojo.location.feature._RESOLVER", {"fn": lambda: locations}),
            (get_unit_tests_scans_path("sarif_aggregated") / "multi_location_result.sarif").open(encoding="utf-8") as testfile,
        ):
            return SarifAggregatedParser().get_findings(testfile, Test())

    def test_scan_type_is_registered(self):
        self.assertIsInstance(get_parser("SARIF Aggregated"), SarifAggregatedParser)

    def test_multi_location_result_is_one_finding_carrying_every_location(self):
        findings = self.parse_multi_location_report(locations=True)
        self.assertEqual(
            2,
            len(findings),
            msg=f"expected one finding per SARIF result, got {len(findings)}: {[(f.file_path, f.line) for f in findings]}",
        )
        multi, single = findings
        # The finding's own coordinates are the result's first location.
        self.assertEqual("src/src/main/java/com/example/stub/StubFile01.java", multi.file_path)
        self.assertEqual(61, multi.line)
        # Every location of the result rides along on the one finding.
        self.assertEqual(
            MULTI_LOCATION_COORDINATES,
            [(loc.data["file_path"], loc.data["line"], loc.data["end_line"]) for loc in multi.unsaved_locations],
        )
        self.assertEqual(1, len(single.unsaved_locations))
        # Locations hold the coordinates, so the description does not repeat them.
        self.assertNotIn("**Locations:**", multi.description)
        # The partial fingerprint identifies the result; with one finding per result it is
        # not repeated inside the report and so not dropped.
        self.assertEqual(MULTI_LOCATION_FINGERPRINT, multi.unique_id_from_tool)
        self.assertEqual(SINGLE_LOCATION_FINGERPRINT, single.unique_id_from_tool)
        for finding in findings:
            self.common_checks(finding)

    def test_multi_location_result_lists_locations_in_description_without_locations_feature(self):
        findings = self.parse_multi_location_report(locations=False)
        self.assertEqual(2, len(findings), msg=f"expected one finding per SARIF result, got {len(findings)}")
        multi, single = findings
        self.assertEqual("src/src/main/java/com/example/stub/StubFile01.java", multi.file_path)
        self.assertEqual(61, multi.line)
        self.assertEqual([], getattr(multi, "unsaved_locations", []))
        # With no Location records to hold them, every coordinate is listed in the description.
        self.assertIn(
            "**Locations:**\n" + "\n".join(f"- {path}:{start}-{end}" for path, start, end in MULTI_LOCATION_COORDINATES),
            multi.description,
        )
        # A single-location result has nothing extra to list.
        self.assertNotIn("**Locations:**", single.description)
        self.assertEqual(MULTI_LOCATION_FINGERPRINT, multi.unique_id_from_tool)
        self.assertEqual(SINGLE_LOCATION_FINGERPRINT, single.unique_id_from_tool)
        for finding in findings:
            self.common_checks(finding)

    def test_get_tests_names_the_test_after_the_tool(self):
        with (get_unit_tests_scans_path("sarif_aggregated") / "multi_location_result.sarif").open(encoding="utf-8") as testfile:
            tests = SarifAggregatedParser().get_tests("SARIF Aggregated", testfile)
        self.assertEqual(1, len(tests))
        self.assertEqual("Stub Scanner", tests[0].type)
        self.assertEqual(2, len(tests[0].findings))

    def parse_result_locations(self, result_locations, *, locations):
        result = {"ruleId": "R1", "level": "error", "message": {"text": "m"}}
        if result_locations is not ...:
            result["locations"] = result_locations
        report = {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Stub Scanner", "rules": [{"id": "R1"}]}}, "results": [result]}],
        }
        with patch.dict("dojo.location.feature._RESOLVER", {"fn": lambda: locations}):
            return SarifAggregatedParser().get_findings(io.StringIO(json.dumps(report)), Test())

    @staticmethod
    def physical(uri, start_line, end_line=None):
        region = {"startLine": start_line}
        if end_line is not None:
            region["endLine"] = end_line
        return {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}

    def test_primary_location_does_not_depend_on_report_order(self):
        ordered = [self.physical("a.py", 3, 5), self.physical("a.py", 10), self.physical("b.py", 1)]
        for locations in (True, False):
            with self.subTest(locations=locations):
                expected = self.parse_result_locations(ordered, locations=locations)[0]
                reordered = self.parse_result_locations(ordered[::-1], locations=locations)[0]
                self.assertEqual(("a.py", 3), (expected.file_path, expected.line))
                self.assertEqual(
                    (expected.file_path, expected.line, expected.description),
                    (reordered.file_path, reordered.line, reordered.description),
                )

    def test_location_without_a_file_is_never_the_primary_location(self):
        logical_only = {"logicalLocations": [{"fullyQualifiedName": "Stub.method"}]}
        findings = self.parse_result_locations([logical_only, self.physical("b.py", 3)], locations=True)
        self.assertEqual(1, len(findings))
        self.assertEqual(("b.py", 3), (findings[0].file_path, findings[0].line))
        self.assertEqual([("b.py", 3)], [(loc.data["file_path"], loc.data["line"]) for loc in findings[0].unsaved_locations])

    def test_end_line_before_start_line_is_not_listed(self):
        findings = self.parse_result_locations([self.physical("a.py", 9, 2), self.physical("b.py", 1)], locations=False)
        self.assertIn("**Locations:**\n- a.py:9\n- b.py:1", findings[0].description)

    def test_missing_or_null_locations(self):
        for result_locations in (..., None, []):
            with self.subTest(result_locations=result_locations):
                findings = self.parse_result_locations(result_locations, locations=True)
                self.assertEqual(1, len(findings))
                self.assertIsNone(findings[0].file_path)
