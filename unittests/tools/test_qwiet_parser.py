import io
import json

from dojo.models import Finding, Test
from dojo.tools.qwiet.parser import QwietParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestQwietParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("qwiet") / filename).open(encoding="utf-8") as file:
            return list(QwietParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(QwietParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def row(self, **overrides):
        row = {"id": "1", "type": "vuln", "category": "SQL Injection", "severity": "critical",
               "title": "A finding", "internal_id": "sl/1", "tags": []}
        row.update(overrides)
        return {"ok": True, "response": [row]}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Qwiet connector's ScanTypeName verbatim.

        Note it does NOT follow the "<Vendor> - Connectors Import" pattern the other connector scan
        types use, so it cannot be derived - it has to be copied.
        """
        parser = QwietParser()
        self.assertEqual(["Qwiet Scan"], parser.get_scan_types())
        self.assertEqual("Qwiet Scan", parser.get_label_for_scan_types("Qwiet Scan"))
        self.assertNotIn("Qwiet - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("qwiet_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("qwiet_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's finding_converter."""
        findings = self.parse("qwiet_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("SQL Injection in ReportController", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("qwiet-sl/00000000-0000-4000-8000-000000000001", finding.unique_id_from_tool)
        self.assertEqual("sl/00000000-0000-4000-8000-000000000001", finding.vuln_id_from_tool)
        self.assertEqual(89, finding.cwe)
        self.assertEqual("src/main/java/com/example/web/ReportController.java", finding.file_path)
        self.assertEqual(88, finding.line)
        self.assertTrue(finding.active)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(["vuln", "a03-injection", "reachability:reachable"], finding.unsaved_tags)
        self.assertIn("reachable", finding.severity_justification)

        self.assertEqual(
            "**Type:** vuln\n"
            "**Category:** SQL Injection\n"
            "**OWASP:** a03-injection\n"
            "**Source:** com.example.web.ReportController.list\n"
            "**Sink:** java.sql.Statement.executeQuery\n"
            "**Locations:** src/main/java/com/example/web/ReportController.java:88, "
            "src/main/java/com/example/db/Reports.java:120\n\n"
            "A request parameter is concatenated into a database query.",
            finding.description,
        )

    def test_most_of_the_data_is_in_tags_not_fields(self):
        """
        Qwiet carries the CVE, package URL, CVSS score, CWE and reachability as key/value TAGS.

        They are a list of {"key", "value"} objects rather than a map, so each is read by key - looking
        for fields of those names would find nothing at all.
        """
        finding = self.by_uid("qwiet_many_vuln.json")["qwiet-sl/00000000-0000-4000-8000-000000000002"]
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual("lib", finding.component_name)
        self.assertEqual("1.2.3", finding.component_version)
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertEqual(502, finding.cwe)

    def test_many_vuln(self):
        self.assertEqual(5, len(self.parse("qwiet_many_vuln.json")))

    def test_the_package_url_is_reduced_to_the_artefact(self):
        """
        "pkg:maven/org.example/lib@1.2.3" is lib 1.2.3.

        Only the last path segment matters: the namespace before it is the group, not the artefact
        DefectDojo matches a component on.
        """
        parser = QwietParser()
        cases = (
            ("pkg:maven/org.example/lib@1.2.3", ("lib", "1.2.3")),
            ("pkg:npm/other-lib@4.5.6", ("other-lib", "4.5.6")),
            ("pkg:npm/@scope/thing@1.0.0", ("thing", "1.0.0")),
            ("lib@1.0.0", ("lib", "1.0.0")),
            ("lib", ("lib", "")),
            ("", ("", "")),
        )
        for purl, expected in cases:
            with self.subTest(purl=purl):
                self.assertEqual(expected, parser.component(purl))

    def test_severity_labels(self):
        for label, expected in (("critical", "Critical"), ("high", "High"), ("medium", "Medium"),
                                ("low", "Low"), ("CRITICAL", "Critical"), ("info", "Info"),
                                ("not a label", "Info"), ("", "Info")):
            with self.subTest(label=label):
                findings = self.parse_string(self.row(severity=label))
                self.assertEqual(expected, findings[0].severity)

    def test_a_dependency_finding_with_related_findings_is_reachable_without_the_tag(self):
        """
        The related findings ARE the path Qwiet traced through the application.

        So a dependency finding that has them is reachable even when no reachability tag is present -
        and reachability is the whole reason to use this tool.
        """
        findings = self.by_uid("qwiet_many_vuln.json")
        reachable = findings["qwiet-sl/00000000-0000-4000-8000-000000000002"]
        self.assertIn("reachability:reachable", reachable.unsaved_tags)
        self.assertIn("attacker-controlled data-flow path", reachable.severity_justification)

    def test_an_unreachable_tag_is_recorded_as_it_is(self):
        finding = self.by_uid("qwiet_many_vuln.json")["qwiet-sl/00000000-0000-4000-8000-000000000003"]
        self.assertIn("reachability:unreachable", finding.unsaved_tags)
        self.assertEqual("Qwiet marks this finding as unreachable.", finding.severity_justification)
        # Reachability does not change the grade - it is context, not a regrade.
        self.assertEqual("Medium", finding.severity)

    def test_no_reachability_information_leaves_the_justification_unset(self):
        finding = self.by_uid("qwiet_many_vuln.json")["qwiet-sl/00000000-0000-4000-8000-000000000005"]
        self.assertIsNone(finding.severity_justification)
        self.assertNotIn("reachability:reachable", finding.unsaved_tags)

    def test_a_location_with_no_line_number_is_still_a_path(self):
        bare_path = self.parse_string(self.row(details={"file_locations": ["src/a.java"]}))
        self.assertEqual("src/a.java", bare_path[0].file_path)
        self.assertIsNone(bare_path[0].line)

    def test_an_unparseable_line_number_keeps_the_path(self):
        """Losing the path because the line was malformed would lose the finding's location."""
        finding = self.by_uid("qwiet_many_vuln.json")["qwiet-sl/00000000-0000-4000-8000-000000000005"]
        self.assertEqual("src/main/java/com/example/Config.java", finding.file_path)
        self.assertIsNone(finding.line)

    def test_only_the_first_location_becomes_the_file_path(self):
        """
        A data-flow finding spans several files and DefectDojo has one file_path.

        The whole list stays in the description so the rest of the path is not lost.
        """
        finding = self.parse("qwiet_one_vuln.json")[0]
        self.assertEqual("src/main/java/com/example/web/ReportController.java", finding.file_path)
        self.assertIn("src/main/java/com/example/db/Reports.java:120", finding.description)

    def test_the_hash_spans_a_file_path_a_cwe_and_a_component(self):
        """
        Qwiet reports both code findings and dependency findings.

        A given finding has a file path or a component, not usually both, so the hash spans all three
        and the unused half hashes as empty.
        """
        self.assertEqual(
            ["title", "severity", "file_path", "cwe", "component_name"],
            QwietParser().get_dedupe_fields(),
        )
        findings = self.by_uid("qwiet_many_vuln.json")
        code = findings["qwiet-sl/00000000-0000-4000-8000-000000000001"]
        self.assertIsNotNone(code.file_path)
        self.assertIsNone(code.component_name)

        dependency = findings["qwiet-sl/00000000-0000-4000-8000-000000000003"]
        self.assertIsNone(dependency.file_path)
        self.assertIsNotNone(dependency.component_name)

    def test_an_unparseable_score_or_cwe_is_left_unset(self):
        findings = self.by_uid("qwiet_many_vuln.json")
        self.assertEqual(0.0, findings["qwiet-sl/00000000-0000-4000-8000-000000000003"].cvssv3_score)
        self.assertEqual(0, findings["qwiet-4"].cwe)

    def test_identity_falls_back_to_the_display_id(self):
        """Qwiet's internal id is stable across scans; the display id is the fallback."""
        finding = self.by_uid("qwiet_many_vuln.json")["qwiet-4"]
        self.assertEqual("Qwiet finding 4", finding.title)
        self.assertIsNone(finding.vuln_id_from_tool)

    def test_title_falls_back_to_the_category(self):
        findings = self.parse_string(self.row(title="", category="SQL Injection"))
        self.assertEqual("SQL Injection", findings[0].title)

    def test_export_shapes(self):
        row = {"id": "1", "type": "vuln", "severity": "low", "title": "A finding", "tags": []}
        for payload in ({"ok": True, "response": [row]}, {"findings": [row]}, [row]):
            with self.subTest(shape=type(payload).__name__):
                self.assertEqual(1, len(self.parse_string(payload)))

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("Qwiet", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("response", str(context.exception))

    def test_malformed_rows_and_tags_are_skipped(self):
        findings = self.parse_string({"response": [
            "not an object",
            None,
            {"id": "1", "type": "vuln", "severity": "low", "title": "A finding",
             "tags": ["not an object", None, {"key": "cwe_category", "value": "CWE-79"}]},
        ]})
        self.assertEqual(1, len(findings))
        self.assertEqual(79, findings[0].cwe)

    def test_severity_is_always_a_known_value(self):
        for filename in ("qwiet_many_vuln.json", "qwiet_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
