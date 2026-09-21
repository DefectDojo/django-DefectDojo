import io
import json

from dojo.models import Finding, Test
from dojo.tools.escape.parser import EscapeParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestEscapeParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("escape") / filename).open(encoding="utf-8") as file:
            return list(EscapeParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(EscapeParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Escape connector's ScanTypeName verbatim.

        Any drift and someone who uploads an export and also syncs the API gets two un-deduplicated
        copies of every issue.
        """
        parser = EscapeParser()
        self.assertEqual(["Escape - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "Escape - Connectors Import",
            parser.get_label_for_scan_types("Escape - Connectors Import"),
        )

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("escape_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("escape_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring IssueToFinding in the connector's converter."""
        findings = self.parse("escape_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("SQL injection in the reports query", finding.title)
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("issue-0001", finding.unique_id_from_tool)
        self.assertEqual(89, finding.cwe)
        self.assertEqual("Use parameterised queries.", finding.mitigation)
        self.assertTrue(finding.active)
        self.assertFalse(finding.static_finding)
        self.assertTrue(finding.dynamic_finding)
        self.assertEqual(["owasp:API8:2023", "method:POST"], finding.unsaved_tags)

        self.assertEqual(
            "A request parameter is concatenated into a database query.\n\n"
            "**Endpoint:** post https://api.example.com/v1/reports\n"
            "**OWASP:** API8:2023\n"
            "**CWE:** CWE-89",
            finding.description,
        )

        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("api.example.com", locations[0].host)
        self.assertEqual("v1/reports", locations[0].path)
        self.assertEqual("https", locations[0].protocol)

    def test_the_application_shape_is_accepted(self):
        """
        The connector reads an application's latest scan, so an export is often the application.

        A bare scan, an application carrying one, an applications list and the issue list itself all
        have to work.
        """
        issue = {"id": "issue-1", "name": "An issue", "severity": "low",
                 "url": "https://api.example.com/v1/thing"}
        shapes = (
            {"issues": [issue]},
            {"lastScan": {"issues": [issue]}},
            {"scan": {"issues": [issue]}},
            {"applications": [{"id": "app-1", "lastScan": {"issues": [issue]}}]},
            [issue],
        )
        for payload in shapes:
            with self.subTest(shape=type(payload).__name__ + str(list(payload)[:1])):
                findings = self.parse_string(payload)
                self.assertEqual(1, len(findings))
                self.assertEqual("An issue", findings[0].title)

    def test_many_vuln(self):
        self.assertEqual(5, len(self.parse("escape_many_vuln.json")))

    def test_severity_labels(self):
        for label, expected in (("critical", "Critical"), ("high", "High"), ("medium", "Medium"),
                                ("low", "Low"), ("info", "Info"), ("HIGH", "High"),
                                ("not a label", "Info"), ("", "Info")):
            with self.subTest(label=label):
                findings = self.parse_string({"issues": [
                    {"id": "issue-1", "name": "An issue", "severity": label},
                ]})
                self.assertEqual(expected, findings[0].severity)

    def test_an_unrecognised_label_is_info(self):
        finding = self.by_uid("escape_many_vuln.json")["issue-0004"]
        self.assertEqual("Info", finding.severity)

    def test_title_falls_back_to_the_issue_id(self):
        finding = self.by_uid("escape_many_vuln.json")["issue-0004"]
        self.assertEqual("Escape issue issue-0004", finding.title)

    def test_the_endpoint_line_carries_the_method(self):
        """
        The same URL behaves differently per verb, which is the whole point of an API scanner.

        When Escape reports no method the line is the URL alone.
        """
        findings = self.by_uid("escape_many_vuln.json")
        self.assertIn(
            "**Endpoint:** post https://api.example.com/v1/reports",
            findings["issue-0001"].description,
        )
        self.assertIn(
            "**Endpoint:** https://api.example.com:8443/v1/search?q=1",
            findings["issue-0003"].description,
        )

    def test_cwe_forms(self):
        for value, expected in (("CWE-89", 89), ("89", 89), ("cwe-89", 89), ("not a cwe", 0),
                                ("", 0), (None, 0)):
            with self.subTest(value=value):
                findings = self.parse_string({"issues": [
                    {"id": "issue-1", "name": "An issue", "severity": "low", "cwe": value},
                ]})
                self.assertEqual(expected, findings[0].cwe)

    def test_a_bare_cwe_number_is_read(self):
        finding = self.by_uid("escape_many_vuln.json")["issue-0002"]
        self.assertEqual(770, finding.cwe)

    def test_an_unparseable_cwe_is_left_unset(self):
        finding = self.by_uid("escape_many_vuln.json")["issue-0003"]
        self.assertEqual(0, finding.cwe)
        # The raw value is still reported, so nothing is lost.
        self.assertIn("**CWE:** not a cwe", finding.description)

    def test_no_remediation_leaves_the_mitigation_unset(self):
        """Escape has no advice for this issue, and the connector does not invent any."""
        finding = self.by_uid("escape_many_vuln.json")["issue-0003"]
        self.assertIsNone(finding.mitigation)

    def test_the_endpoint_records_scheme_port_path_and_query(self):
        """
        This scan type's deduplication hashes the endpoints, so the tested URL is always recorded.

        An unpopulated endpoint would leave the hash computed over nothing and every rescan would
        reimport.
        """
        finding = self.by_uid("escape_many_vuln.json")["issue-0003"]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("api.example.com", locations[0].host)
        self.assertEqual(8443, locations[0].port)
        self.assertEqual("v1/search", locations[0].path)
        self.assertEqual("q=1", locations[0].query)

    def test_an_issue_with_no_url_records_no_endpoint(self):
        finding = self.by_uid("escape_many_vuln.json")["issue-0005"]
        self.assertEqual([], self.get_unsaved_locations(finding))
        self.assertNotIn("**Endpoint:**", finding.description)

    def test_tags_carry_the_owasp_category_and_the_method(self):
        findings = self.by_uid("escape_many_vuln.json")
        self.assertEqual(["owasp:API4:2023", "method:POST"], findings["issue-0002"].unsaved_tags)
        self.assertEqual(["method:GET"], findings["issue-0004"].unsaved_tags)
        self.assertEqual(["owasp:API9:2023"], findings["issue-0005"].unsaved_tags)
        self.assertEqual([], findings["issue-0003"].unsaved_tags)

    def test_the_method_tag_is_uppercased(self):
        finding = self.by_uid("escape_many_vuln.json")["issue-0001"]
        self.assertIn("method:POST", finding.unsaved_tags)
        # The description keeps Escape's own casing, as the connector does.
        self.assertIn("**Endpoint:** post ", finding.description)

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("Escape", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("issues", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"issues": [
            "not an object",
            None,
            {"id": "issue-1", "name": "An issue", "severity": "low"},
        ]})
        self.assertEqual(1, len(findings))

    def test_severity_is_always_a_known_value(self):
        for filename in ("escape_many_vuln.json", "escape_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
