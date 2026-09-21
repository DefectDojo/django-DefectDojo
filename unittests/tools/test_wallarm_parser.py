import io
import json
from datetime import UTC, datetime

from dojo.models import Finding, Test
from dojo.tools.wallarm.parser import WallarmParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestWallarmParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("wallarm") / filename).open(encoding="utf-8") as file:
            return list(WallarmParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(WallarmParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def row(self, **overrides):
        row = {"id": 1, "title": "A vulnerability", "type": "sqli", "status": "active",
               "threat": "high", "domain": "api.example.com", "path": "/v1/thing"}
        row.update(overrides)
        return {"status": 200, "body": [row]}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Wallarm connector's ScanTypeName verbatim.

        Note it does NOT follow the "<Vendor> - Connectors Import" pattern the other connector scan
        types use, so it cannot be derived - it has to be copied.
        """
        parser = WallarmParser()
        self.assertEqual(["Wallarm API Security"], parser.get_scan_types())
        self.assertEqual("Wallarm API Security", parser.get_label_for_scan_types("Wallarm API Security"))
        self.assertNotIn("Wallarm - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        """Closed and false-positive vulnerabilities have already been dealt with in Wallarm."""
        self.assertEqual(0, len(self.parse("wallarm_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("wallarm_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's converter."""
        findings = self.parse("wallarm_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("SQL injection in the reports endpoint", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("wallarm-700001", finding.unique_id_from_tool)
        self.assertEqual("sqli", finding.vuln_id_from_tool)
        self.assertEqual("POST /v1/reports with filter=1' OR '1'='1", finding.mitigation)
        self.assertEqual(datetime(2024, 7, 1, tzinfo=UTC).date(), finding.date)
        self.assertTrue(finding.active)
        self.assertFalse(finding.static_finding)
        self.assertTrue(finding.dynamic_finding)
        self.assertEqual(["sqli", "active"], finding.unsaved_tags)
        self.assertEqual(["CVE-2000-0001", "CVE-2000-0002"], finding.unsaved_vulnerability_ids)

        self.assertEqual(
            "**Type:** sqli\n"
            "**Domain:** api.example.com\n"
            "**Method:** POST\n"
            "**Path:** /v1/reports\n"
            "**Parameter:** post_body|json_doc|hash|filter\n"
            "**Detection method:** active_verification\n\n"
            "**Description:**\n"
            "A request parameter reaches a database query. Related to CVE-2000-0002 and cve-2000-0002.\n\n"
            "**Additional:**\n"
            "Validated against the running service. See CVE-2000-0001.",
            finding.description,
        )

        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("api.example.com", locations[0].host)
        self.assertEqual("v1/reports", locations[0].path)

    def test_many_vuln(self):
        """Seven rows, two of them already dealt with."""
        self.assertEqual(5, len(self.parse("wallarm_many_vuln.json")))

    def test_closed_and_false_positive_are_skipped(self):
        for status, imported in (("active", 1), ("closed", 0), ("falsepositive", 0),
                                 ("CLOSED", 0), ("", 1)):
            with self.subTest(status=status):
                self.assertEqual(imported, len(self.parse_string(self.row(status=status))))

    def test_the_threat_level_may_be_a_number_or_a_word(self):
        """
        Wallarm sends the threat level in one field as either form, depending on which API answered.

        The two need different ladders, and reading a number as a label - or the other way round -
        would drop everything to Info.
        """
        for threat, expected in ((5, "Critical"), (6, "Critical"), (4, "High"), (3, "Medium"),
                                 (2, "Low"), (1, "Info"), (0, "Info"), (5.0, "Critical"),
                                 ("critical", "Critical"), ("high", "High"), ("medium", "Medium"),
                                 ("low", "Low"), ("info", "Info"), ("information", "Info"),
                                 ("informational", "Info"), ("", "Info"), ("severe", "Info"),
                                 (None, "Info")):
            with self.subTest(threat=threat):
                findings = self.parse_string(self.row(threat=threat))
                self.assertEqual(expected, findings[0].severity)

    def test_the_numeric_scale_runs_to_five(self):
        """
        Five is the most severe, not the least - the inverse of a priority number.

        This is the one part of the mapping the vendor's documentation does not pin down, so it is
        copied from the connector rather than inferred, and flagged in the PR as worth confirming
        against a live tenant.
        """
        findings = self.by_uid("wallarm_many_vuln.json")
        self.assertEqual("Critical", findings["wallarm-700001"].severity)
        self.assertEqual("Medium", findings["wallarm-wid-0003"].severity)

    def test_an_unrecognised_label_is_info(self):
        findings = self.by_uid("wallarm_many_vuln.json")
        self.assertEqual("Info", findings["wallarm-700007"].severity)

    def test_the_unique_id_falls_back_to_the_wid_then_the_location(self):
        """
        The location fallback is last because it is the only one that is not an id.

        Two vulnerabilities of different types on one path would collide, but something stable is
        better than nothing.
        """
        findings = self.by_uid("wallarm_many_vuln.json")
        self.assertIn("wallarm-700001", findings)
        self.assertIn("wallarm-wid-0003", findings)
        self.assertIn("wallarm-legacy.example.com/old", findings)

    def test_title_falls_back_to_the_type_then_the_id(self):
        by_type = self.parse_string(self.row(title="", type="xss"))
        self.assertEqual("Wallarm: xss", by_type[0].title)

        bare = self.parse_string(self.row(title="", type="", id=42))
        self.assertEqual("Wallarm vulnerability 42", bare[0].title)

    def test_identifiers_are_sorted_and_deduplicated_case_insensitively(self):
        """
        Wallarm's extractor sorts and drops case-insensitive duplicates.

        The sample names the same CVE twice in different cases and another in the additional text.
        """
        finding = self.by_uid("wallarm_many_vuln.json")["wallarm-700001"]
        self.assertEqual(["CVE-2000-0001", "CVE-2000-0002"], finding.unsaved_vulnerability_ids)

    def test_a_finding_with_no_identifiers_has_none(self):
        finding = self.by_uid("wallarm_many_vuln.json")["wallarm-700002"]
        self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_only_an_absolute_path_is_appended_to_the_endpoint(self):
        """
        Wallarm uses the path field for a parameter location on some vulnerability types.

        The connector only appends a value beginning with "/", because anything else is not a path.
        """
        findings = self.by_uid("wallarm_many_vuln.json")
        with_path = self.get_unsaved_locations(findings["wallarm-700001"])[0]
        self.assertEqual("v1/reports", with_path.path)

        without = self.get_unsaved_locations(findings["wallarm-wid-0003"])[0]
        self.assertEqual("shop.example.com", without.host)
        self.assertFalse(without.path)
        # The raw value is still reported, so nothing is lost.
        self.assertIn("**Path:** not-a-path", findings["wallarm-wid-0003"].description)

    def test_a_row_with_no_domain_records_no_endpoint(self):
        findings = self.parse_string(self.row(domain=""))
        self.assertEqual([], self.get_unsaved_locations(findings[0]))

    def test_dates_are_unix_seconds(self):
        findings = self.by_uid("wallarm_many_vuln.json")
        self.assertEqual(datetime(2024, 7, 1, tzinfo=UTC).date(), findings["wallarm-700001"].date)
        self.assertEqual(datetime(2024, 6, 1, tzinfo=UTC).date(), findings["wallarm-700002"].date)

    def test_a_row_with_no_validation_time_keeps_the_default_date(self):
        finding = self.by_uid("wallarm_many_vuln.json")["wallarm-wid-0003"]
        self.assertEqual(datetime.now(tz=UTC).date(), finding.date)

    def test_the_exploit_example_is_the_mitigation(self):
        """
        Wallarm offers an exploit example rather than advice, and the connector puts it here.

        Mirrored rather than left out: it is the only remediation-shaped field Wallarm has, and a
        reviewer can act on a reproduction. Flagged in the PR as a follow-up for both sides.
        """
        finding = self.by_uid("wallarm_many_vuln.json")["wallarm-700002"]
        self.assertEqual("Forge a token using the none algorithm.", finding.mitigation)

    def test_a_row_with_no_prose_has_only_the_field_lines(self):
        findings = self.parse_string(self.row(method="POST", description="", additional="",
                                              parameter="", detection_method=""))
        self.assertEqual(
            "**Type:** sqli\n"
            "**Domain:** api.example.com\n"
            "**Method:** POST\n"
            "**Path:** /v1/thing",
            findings[0].description,
        )

    def test_absent_location_fields_are_omitted_rather_than_left_blank(self):
        findings = self.parse_string(self.row(description="", additional=""))
        self.assertNotIn("**Method:**", findings[0].description)
        self.assertNotIn("**Parameter:**", findings[0].description)
        self.assertNotIn("**Detection method:**", findings[0].description)

    def test_a_bare_list_of_vulnerabilities_is_accepted(self):
        findings = self.parse_string([
            {"id": 1, "title": "A vulnerability", "type": "sqli", "status": "active", "threat": 4,
             "domain": "api.example.com"},
        ])
        self.assertEqual(1, len(findings))
        self.assertEqual("High", findings[0].severity)

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("Wallarm", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("body", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"body": [
            "not an object",
            None,
            {"id": 1, "title": "A vulnerability", "type": "sqli", "status": "active", "threat": 4,
             "domain": "api.example.com"},
        ]})
        self.assertEqual(1, len(findings))

    def test_severity_is_always_a_known_value(self):
        for filename in ("wallarm_many_vuln.json", "wallarm_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
