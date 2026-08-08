import io
import json

from dojo.models import Finding, Test
from dojo.tools.parasoft.parser import ParasoftParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestParasoftParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("parasoft") / filename
        with path.open(encoding="utf-8") as file:
            return list(ParasoftParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(ParasoftParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def row(self, **overrides):
        row = {"hash": "h1", "rule": "RULE-1", "message": "A violation", "severity": 2,
               "locFile": "src/generic/a.c", "locStartLine": 10}
        row.update(overrides)
        return {"staticAnalysisViolations": [row]}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Parasoft connector's ScanTypeName verbatim.

        Note it does NOT follow the "<Vendor> - Connectors Import" pattern the other connector scan
        types use, so it cannot be derived - it has to be copied.
        """
        parser = ParasoftParser()
        self.assertEqual(["Parasoft DTP Scan"], parser.get_scan_types())
        self.assertEqual("Parasoft DTP Scan", parser.get_label_for_scan_types("Parasoft DTP Scan"))
        self.assertNotIn("Parasoft - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("parasoft_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("parasoft_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's finding_converter."""
        findings = self.parse("parasoft_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("CERT_C-INT30-a: Unsigned integer operation may wrap around", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("parasoft-a1b2c3d4e5f60718", finding.unique_id_from_tool)
        self.assertEqual("CERT_C-INT30-a", finding.vuln_id_from_tool)
        self.assertEqual("src/generic/parser.c", finding.file_path)
        self.assertEqual(128, finding.line)
        self.assertTrue(finding.active)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(["CERT_C-INT30-a", "Integers",
                          "com.parasoft.xtest.cpp.analyzer.static.pattern", "c"],
                         finding.unsaved_tags)
        self.assertEqual(
            "**Message:** Unsigned integer operation may wrap around\n"
            "**Rule:** CERT_C-INT30-a\n"
            "**Category:** Integers\n"
            "**Analyzer:** com.parasoft.xtest.cpp.analyzer.static.pattern\n"
            "**Language:** c",
            finding.description,
        )

    def test_many_vuln(self):
        self.assertEqual(6, len(self.parse("parasoft_many_vuln.json")))

    def test_severity_one_is_the_most_severe(self):
        """
        DTP's numeric severity is the inverse of a score: 1 is critical, 5 is informational.

        Reading it as a score would invert the entire ladder.
        """
        for code, expected in ((1, "Critical"), (2, "High"), (3, "Medium"), (4, "Low"), (5, "Info"),
                               (0, "Info"), (9, "Info"), (None, "Info")):
            with self.subTest(code=code):
                findings = self.parse_string(self.row(severity=code))
                self.assertEqual(expected, findings[0].severity)

    def test_a_quoted_severity_and_line_are_accepted(self):
        finding = self.by_uid("parasoft_many_vuln.json")["parasoft-v-900002"]
        self.assertEqual("High", finding.severity)
        self.assertEqual(64, finding.line)

    def test_the_identity_prefers_the_violation_hash(self):
        """
        DTP's hash is what stays stable as a file is edited around the violation.

        The rule-plus-file fallback would merge two violations of one rule in one file, so the hash
        and then the id are preferred.
        """
        findings = self.by_uid("parasoft_many_vuln.json")
        self.assertIn("parasoft-a1b2c3d4e5f60718", findings)
        # No hash, so the violation id is used.
        self.assertIn("parasoft-v-900002", findings)
        # Neither, so the rule and the file.
        self.assertIn("parasoft-PB.NUM.CLP-src/generic/util.java", findings)

    def test_the_title_falls_back_through_the_message_and_the_rule(self):
        findings = self.by_uid("parasoft_many_vuln.json")
        self.assertEqual("PB.NUM.CLP", findings["parasoft-PB.NUM.CLP-src/generic/util.java"].title)
        self.assertEqual("A violation with no rule id",
                         findings["parasoft--src/generic/other.c"].title)
        self.assertEqual("Parasoft DTP violation", findings["parasoft--"].title)

    def test_a_violation_with_no_rule_has_no_rule_id(self):
        finding = self.by_uid("parasoft_many_vuln.json")["parasoft--src/generic/other.c"]
        self.assertIsNone(finding.vuln_id_from_tool)

    def test_identifiers_named_in_the_message_are_extracted_and_sorted(self):
        """
        Rare for static analysis, but a rule that names a CVE is worth linking.

        The connector's shared extractor sorts its results, so the order is alphabetical rather than
        the order they appear - the fixture names CVE-2000-0002 first.
        """
        finding = self.by_uid("parasoft_many_vuln.json")["parasoft-v-900002"]
        self.assertEqual(["CVE-2000-0001", "CVE-2000-0002"], finding.unsaved_vulnerability_ids)

    def test_an_identifier_in_the_rule_id_is_also_read(self):
        findings = self.parse_string(self.row(rule="CVE-2000-0005", message="A violation"))
        self.assertEqual(["CVE-2000-0005"], findings[0].unsaved_vulnerability_ids)

    def test_non_cve_advisory_formats_are_recognised(self):
        for identifier in ("GHSA-aaaa-bbbb-cccc", "GO-2024-1234", "RHSA-2024:1234"):
            with self.subTest(identifier=identifier):
                findings = self.parse_string(self.row(message=f"see {identifier}"))
                self.assertEqual([identifier], findings[0].unsaved_vulnerability_ids)

    def test_a_violation_naming_no_identifier_has_none(self):
        finding = self.by_uid("parasoft_many_vuln.json")["parasoft-a1b2c3d4e5f60718"]
        self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_a_violation_with_no_line_has_none(self):
        finding = self.by_uid("parasoft_many_vuln.json")["parasoft-MISRA-1-src/generic/info.c"]
        self.assertIsNone(finding.line)
        self.assertEqual("src/generic/info.c", finding.file_path)

    def test_a_violation_with_no_file_has_no_path(self):
        finding = self.by_uid("parasoft_many_vuln.json")["parasoft--"]
        self.assertIsNone(finding.file_path)

    def test_absent_description_fields_are_left_out(self):
        finding = self.by_uid("parasoft_many_vuln.json")["parasoft-PB.NUM.CLP-src/generic/util.java"]
        self.assertNotIn("**Message:**", finding.description)
        self.assertNotIn("**Analyzer:**", finding.description)
        self.assertIn("**Rule:** PB.NUM.CLP", finding.description)
        self.assertIn("**Language:** java", finding.description)

    def test_export_shapes(self):
        row = {"hash": "h1", "rule": "RULE-1", "message": "A violation", "severity": 2}
        for payload in ([row], {"staticAnalysisViolations": [row]}, {"violations": [row]},
                        {"data": [row]}, {"results": [row]}):
            with self.subTest(shape=str(payload)[:26]):
                self.assertEqual(1, len(self.parse_string(payload)))

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("Parasoft", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("staticAnalysisViolations", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"staticAnalysisViolations": [
            "not an object",
            None,
            {"hash": "h9", "rule": "RULE-9", "message": "A violation", "severity": 3},
        ]})
        self.assertEqual(1, len(findings))
        self.assertEqual("parasoft-h9", findings[0].unique_id_from_tool)

    def test_the_file_path_and_the_rule_are_both_in_the_hash(self):
        """The same rule firing in two files is two violations to fix."""
        self.assertEqual(["title", "severity", "file_path", "vuln_id_from_tool"],
                         ParasoftParser().get_dedupe_fields())

    def test_severity_is_always_a_known_value(self):
        for filename in ("parasoft_many_vuln.json", "parasoft_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
