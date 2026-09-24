import io
import json
from datetime import UTC, datetime

from dojo.models import Finding, Test
from dojo.tools.strix.parser import StrixParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestStrixParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("strix") / filename).open(encoding="utf-8") as file:
            return list(StrixParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = StrixParser()
        self.assertEqual(["Strix Scan"], parser.get_scan_types())
        self.assertEqual("Strix Scan", parser.get_label_for_scan_types("Strix Scan"))
        self.assertIn("vulnerabilities.json", parser.get_description_for_scan_types("Strix Scan"))

    def test_no_vuln(self):
        self.assertEqual([], self.parse("strix_no_vuln.json"))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("strix_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a representative Strix run report."""
        finding = self.parse("strix_one_vuln.json")[0]

        self.assertEqual("Legacy jobs.list handler bypasses task and queue permission filtering", finding.title)
        self.assertEqual("vuln-0001", finding.vuln_id_from_tool)
        self.assertEqual("Medium", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual(862, finding.cwe)
        self.assertTrue(finding.dynamic_finding)
        self.assertFalse(finding.static_finding)
        self.assertEqual(
            datetime(2026, 9, 23, 7, 13, 47, tzinfo=UTC),
            finding.date,
        )
        self.assertEqual(4.3, finding.cvssv3_score)
        self.assertTrue(finding.fix_available)

        self.assertIn("**Target:** /workspace/sample-app", finding.description)
        self.assertIn("**Confidence:** medium", finding.description)
        self.assertIn("**CVSS:** 4.3 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N)", finding.description)
        self.assertIn("## Technical analysis", finding.description)
        self.assertIn("## Evidence", finding.description)
        self.assertIn("## Assumptions", finding.description)
        self.assertIn("## Counter-evidence", finding.description)
        self.assertIn("## Conditions that would change severity", finding.description)

        self.assertIn("Call `POST /v2.0/jobs.list`", finding.steps_to_reproduce)
        self.assertIn("```python", finding.steps_to_reproduce)
        self.assertIn("jobs.list", finding.steps_to_reproduce)

        self.assertIn("`PermissionsFilter`-based redaction", finding.mitigation)
        self.assertIn("**Fix effort:** low", finding.mitigation)

        self.assertIn("learn the id and name", finding.impact)

    def test_many_vuln(self):
        findings = self.parse("strix_many_vulns.json")
        self.assertEqual(3, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)

    def test_dependency_finding_mapping(self):
        """dependency_cve findings carry package metadata and a CVE identifier."""
        finding = next(f for f in self.parse("strix_many_vulns.json") if f.vuln_id_from_tool == "vuln-0002")

        self.assertEqual("Info", finding.severity)
        self.assertEqual(347, finding.cwe)
        self.assertEqual(["CVE-2026-48526"], finding.unsaved_vulnerability_ids)
        self.assertEqual("pyjwt", finding.component_name)
        self.assertEqual("2.12.1", finding.component_version)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertIn("**CVSS:** 0.0", finding.description)

    def test_code_location_mapping(self):
        """code_locations anchor the finding to a file and line."""
        finding = next(f for f in self.parse("strix_many_vulns.json") if f.vuln_id_from_tool == "vuln-0017")

        self.assertEqual("server/services/sessions.py", finding.file_path)
        self.assertEqual(42, finding.line)
        self.assertEqual(331, finding.cwe)
        self.assertEqual(7.5, finding.cvssv3_score)

    def test_minimal_finding_uses_defaults(self):
        """Fields are optional per finding class; missing ones stay empty."""
        finding = next(f for f in self.parse("strix_many_vulns.json") if f.vuln_id_from_tool == "vuln-0020")

        self.assertEqual("Low", finding.severity)
        self.assertIsNone(finding.cwe)
        self.assertIsNone(finding.file_path)
        self.assertIsNone(finding.steps_to_reproduce)
        self.assertIsNone(finding.cvssv3_score)
        self.assertTrue(finding.fix_available)
        self.assertNotIn("## Evidence", finding.description)
        self.assertNotIn("**Confidence:**", finding.description)
        self.assertNotIn("**CVSS:**", finding.description)

    def test_severity_map(self):
        parser = StrixParser()
        for level, expected in [
            ("critical", "Critical"),
            ("high", "High"),
            ("medium", "Medium"),
            ("low", "Low"),
            ("info", "Info"),
        ]:
            self.assertEqual(expected, parser._severity(level))

        self.assertEqual("Info", parser._severity("severe"))
        self.assertEqual("Info", parser._severity(None))

    def test_cwe_extraction(self):
        parser = StrixParser()
        self.assertEqual(862, parser._cwe("CWE-862"))
        self.assertEqual(79, parser._cwe("CWE-79: Improper Neutralization of Input"))
        self.assertIsNone(parser._cwe(None))
        self.assertIsNone(parser._cwe("no identifier here"))

    def test_cvss_vector_from_breakdown(self):
        parser = StrixParser()
        self.assertIsNone(parser._cvss_vector(None))
        self.assertIsNone(parser._cvss_vector({}))
        self.assertIsNone(parser._cvss_vector({"attack_vector": "N"}))
        self.assertEqual(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            parser._cvss_vector({
                "attack_vector": "N",
                "attack_complexity": "L",
                "privileges_required": "N",
                "user_interaction": "N",
                "scope": "U",
                "confidentiality": "H",
                "integrity": "N",
                "availability": "N",
            }),
        )

    def test_wrapped_report_shape_is_accepted(self):
        with (get_unit_tests_scans_path("strix") / "strix_one_vuln.json").open(encoding="utf-8") as file:
            report = io.StringIO(json.dumps({"vulnerabilities": json.load(file)}))
        findings = list(StrixParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("vuln-0001", findings[0].vuln_id_from_tool)

    def test_empty_entries_are_skipped(self):
        report = io.StringIO(json.dumps([None, {}]))
        self.assertEqual([], list(StrixParser().get_findings(report, Test())))

    def test_finding_without_remediation_has_no_fix_available(self):
        report = io.StringIO(json.dumps([{
            "id": "vuln-0003",
            "title": "No fix proposed yet",
            "severity": "low",
            "description": "Awaiting triage.",
        }]))
        finding = list(StrixParser().get_findings(report, Test()))[0]
        self.assertFalse(finding.fix_available)
        self.assertIsNone(finding.mitigation)

    def test_wrong_shape_is_rejected(self):
        with self.assertRaises(TypeError):
            list(StrixParser().get_findings(io.StringIO('{"run": "x"}'), Test()))
        with self.assertRaises(TypeError):
            list(StrixParser().get_findings(io.StringIO('"a string"'), Test()))
