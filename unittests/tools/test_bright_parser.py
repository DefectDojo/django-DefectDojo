import io
import json

from dojo.models import Finding, Test
from dojo.tools.bright.parser import BrightParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestBrightParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("bright") / filename).open(encoding="utf-8") as file:
            return list(BrightParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(BrightParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Bright connector's ScanTypeName verbatim.

        Any drift and someone who uploads an export and also syncs the API gets two un-deduplicated
        copies of every issue.
        """
        parser = BrightParser()
        self.assertEqual(["Bright - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "Bright - Connectors Import",
            parser.get_label_for_scan_types("Bright - Connectors Import"),
        )

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("bright_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("bright_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring IssueToFinding in the connector's converter."""
        findings = self.parse("bright_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Reflected cross-site scripting", finding.title)
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("issue-0001", finding.unique_id_from_tool)
        self.assertEqual(6.1, finding.cvssv3_score)
        self.assertEqual(79, finding.cwe)
        self.assertEqual("Encode user input before rendering it.", finding.mitigation)
        self.assertEqual("https://app.example.com/search?q=1", finding.references)
        self.assertTrue(finding.active)
        self.assertFalse(finding.static_finding)
        self.assertTrue(finding.dynamic_finding)

        self.assertEqual(
            "A request parameter is reflected into the response without encoding.\n\n"
            "**Entry Point:** https://app.example.com/search?q=1\n"
            "**Protocol:** http\n"
            "**CWE:** CWE-79\n"
            "\n**Request:**\n```\n"
            "GET /search?q=%3Cscript%3E HTTP/1.1\nHost: app.example.com\n"
            "```\n"
            "\n**Response:**\n```\n"
            "HTTP/1.1 200 OK\n\n<html><script>\n"
            "```",
            finding.description,
        )

        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("app.example.com", locations[0].host)
        self.assertEqual("search", locations[0].path)
        self.assertEqual("q=1", locations[0].query)

    def test_the_request_and_response_are_fenced_not_rendered(self):
        """
        Both are raw HTTP captured from the target, so they must not be read as markup.

        A reviewer also needs them verbatim to reproduce, which is why they are fenced rather than
        summarised or escaped.
        """
        finding = self.parse("bright_one_vuln.json")[0]
        self.assertIn("**Request:**\n```\n", finding.description)
        self.assertIn("**Response:**\n```\n", finding.description)
        # The captured markup survives inside the fence rather than being stripped.
        self.assertIn("<html><script>", finding.description)

    def test_many_vuln(self):
        self.assertEqual(4, len(self.parse("bright_many_vuln.json")))

    def test_severity_labels(self):
        for label, expected in (("Critical", "Critical"), ("High", "High"), ("Medium", "Medium"),
                                ("Low", "Low"), ("low", "Low"), ("not a label", "Info"), ("", "Info")):
            with self.subTest(label=label):
                findings = self.parse_string([{"id": "issue-1", "name": "An issue", "severity": label}])
                self.assertEqual(expected, findings[0].severity)

    def test_an_unrecognised_severity_is_info(self):
        finding = self.by_uid("bright_many_vuln.json")["issue-0003"]
        self.assertEqual("Info", finding.severity)

    def test_title_falls_back_to_the_issue_id(self):
        finding = self.by_uid("bright_many_vuln.json")["issue-0003"]
        self.assertEqual("Bright issue issue-0003", finding.title)

    def test_a_score_may_arrive_as_a_string(self):
        finding = self.by_uid("bright_many_vuln.json")["issue-0002"]
        self.assertEqual(3.1, finding.cvssv3_score)

    def test_a_zero_score_is_left_unset(self):
        finding = self.by_uid("bright_many_vuln.json")["issue-0003"]
        self.assertIsNone(finding.cvssv3_score)

    def test_cwe_forms(self):
        for value, expected in (("CWE-79", 79), ("79", 79), ("cwe-79", 79), ("not a cwe", 0), ("", 0)):
            with self.subTest(value=value):
                findings = self.parse_string([
                    {"id": "issue-1", "name": "An issue", "severity": "low", "cwe": value},
                ])
                self.assertEqual(expected, findings[0].cwe)

    def test_a_bare_cwe_number_is_read(self):
        finding = self.by_uid("bright_many_vuln.json")["issue-0002"]
        self.assertEqual(693, finding.cwe)

    def test_an_unparseable_cwe_still_appears_in_the_description(self):
        finding = self.by_uid("bright_many_vuln.json")["issue-0003"]
        self.assertEqual(0, finding.cwe)
        self.assertIn("**CWE:** not a cwe", finding.description)

    def test_the_entry_point_is_the_endpoint(self):
        """
        This scan type's deduplication hashes the endpoints, so one is always recorded.

        An unpopulated endpoint would leave the hash computed over nothing and every rescan would
        reimport.
        """
        finding = self.by_uid("bright_many_vuln.json")["issue-0001"]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("app.example.com", locations[0].host)

    def test_the_resources_are_the_endpoint_fallback(self):
        """
        Bright reports one issue against several resources when the same weakness is reachable from
        more than one URL, so with no entry point every resource is recorded.
        """
        findings = self.by_uid("bright_many_vuln.json")
        locations = self.get_unsaved_locations(findings["issue-0002"])
        self.assertEqual(2, len(locations))
        self.assertEqual({"app.example.com", "api.example.com"}, {loc.host for loc in locations})
        self.assertIn(8443, {loc.port for loc in locations})

        # An empty entry point falls back the same way.
        single = self.get_unsaved_locations(findings["issue-0004"])
        self.assertEqual(1, len(single))
        self.assertEqual("api.example.com", single[0].host)

    def test_an_entry_point_that_cannot_be_a_host_is_not_recorded(self):
        """
        DefectDojo's host field would reject it, and a ValidationError fails the whole import rather
        than the one finding. The entry point is still in the description.
        """
        finding = self.by_uid("bright_many_vuln.json")["issue-0003"]
        self.assertEqual([], self.get_unsaved_locations(finding))
        self.assertIn("**Entry Point:** an internal service", finding.description)

    def test_references_are_the_resources_one_per_line(self):
        finding = self.by_uid("bright_many_vuln.json")["issue-0002"]
        self.assertEqual(
            "https://app.example.com/\nhttps://api.example.com:8443/v1/health",
            finding.references,
        )

    def test_no_remediation_leaves_the_mitigation_unset(self):
        finding = self.by_uid("bright_many_vuln.json")["issue-0002"]
        self.assertIsNone(finding.mitigation)

    def test_export_shapes(self):
        """Bright's issues endpoint answers with a bare array; a scan object carries it nested."""
        issue = {"id": "issue-1", "name": "An issue", "severity": "low"}
        for payload in ([issue], {"issues": [issue]}, {"items": [issue]},
                        {"scan": {"issues": [issue]}}, {"data": {"issues": [issue]}}):
            with self.subTest(shape=type(payload).__name__ + str(list(payload)[:1])):
                findings = self.parse_string(payload)
                self.assertEqual(1, len(findings))
                self.assertEqual("An issue", findings[0].title)

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("Bright", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("issues", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string(["not an object", None,
                                      {"id": "issue-1", "name": "An issue", "severity": "low"}])
        self.assertEqual(1, len(findings))

    def test_severity_is_always_a_known_value(self):
        for filename in ("bright_many_vuln.json", "bright_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
