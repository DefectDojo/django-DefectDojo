import io
import json
from datetime import UTC, date, datetime

from dojo.models import Finding, Test
from dojo.tools.groupib.parser import GroupibParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestGroupibParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("groupib") / filename
        with path.open(encoding="utf-8") as file:
            return list(GroupibParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(GroupibParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def issue(self, lifecycle="Detected", **body):
        """
        One issue. Note the two different "status" fields Group-IB uses.

        The LIFECYCLE status is the issue's own; the severity label is the one inside its body. The
        helper names them apart because a single keyword cannot mean both - which is the same confusion
        the parser exists to resolve.
        """
        row = {"category": "Vulnerability", "type": "An issue", "status": "High severity"}
        row.update(body)
        return {"items": [{"id": "issue-1", "status": lifecycle, "body": row}]}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """Must equal the Group-IB connector's ScanTypeName verbatim."""
        parser = GroupibParser()
        self.assertEqual(["Group-IB ASM - Connectors Import"], parser.get_scan_types())
        self.assertEqual("Group-IB ASM - Connectors Import",
                         parser.get_label_for_scan_types("Group-IB ASM - Connectors Import"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("groupib_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("groupib_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring ConvertIssue in the connector's issue_converter."""
        findings = self.parse("groupib_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Exposed administrative interface", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("issue-0001", finding.unique_id_from_tool)
        self.assertEqual("Exposed administrative interface", finding.vuln_id_from_tool)
        self.assertEqual(date(2024, 6, 2), finding.date)
        self.assertTrue(finding.active)
        self.assertFalse(finding.is_mitigated)
        self.assertFalse(finding.false_p)
        self.assertFalse(finding.out_of_scope)
        # ASM findings come from external scanning.
        self.assertFalse(finding.static_finding)
        self.assertTrue(finding.dynamic_finding)
        self.assertEqual(["mitre-attack:T1190", "mitre-attack:T1595"], finding.unsaved_tags)
        self.assertEqual(
            "**Category:** Vulnerability\n"
            "**Type:** Exposed administrative interface\n"
            "**Asset:** admin.example.com\n"
            "**Asset status:** Confirmed\n"
            "**Asset discovered:** 2024-05-01\n"
            "**Reason:** The management console is reachable from the internet\n"
            "**Details:** The console accepted a connection from an external address.\n"
            "**Context:** Discovered during external scanning.",
            finding.description,
        )

        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("admin.example.com", locations[0].host)

    def test_many_vuln(self):
        self.assertEqual(6, len(self.parse("groupib_many_vuln.json")))

    def test_the_severity_is_the_body_status_not_the_issue_status(self):
        """
        Two fields are called "status" and mean different things.

        The issue's own status is its lifecycle state; the one in its body is the SEVERITY label.
        Reading the lifecycle status as a severity would grade every finding Info.
        """
        finding = self.by_uid("groupib_many_vuln.json")["issue-0001"]
        self.assertEqual("Critical", finding.severity)
        self.assertTrue(finding.active)

    def test_severity_labels_are_matched_by_containment(self):
        """Group-IB writes the severity as a phrase, so equality would never match."""
        for label, expected in (("Critical severity", "Critical"), ("High severity", "High"),
                                ("Medium severity", "Medium"), ("Low severity", "Low"),
                                ("Info severity", "Info"), ("critical", "Critical"),
                                ("a label it does not use", "Info"), ("", "Info")):
            with self.subTest(label=label):
                findings = self.parse_string(self.issue(status=label))
                self.assertEqual(expected, findings[0].severity)

    def test_the_worse_keyword_wins_when_a_label_names_two(self):
        findings = self.parse_string(self.issue(status="Critical, was High severity"))
        self.assertEqual("Critical", findings[0].severity)

    def test_the_lifecycle_status_sets_the_right_flag(self):
        """
        The three closing states mean different things and are kept apart.

        A solved issue was fixed, an ignored one was accepted, and a false positive was never real.
        """
        findings = self.by_uid("groupib_many_vuln.json")

        solved = findings["issue-0002"]
        self.assertFalse(solved.active)
        self.assertTrue(solved.is_mitigated)
        self.assertFalse(solved.false_p)

        false_positive = findings["issue-0003"]
        self.assertFalse(false_positive.active)
        self.assertTrue(false_positive.false_p)
        self.assertFalse(false_positive.is_mitigated)

        ignored = findings["issue-0004"]
        self.assertFalse(ignored.active)
        self.assertTrue(ignored.out_of_scope)
        self.assertFalse(ignored.false_p)

    def test_open_and_unrecognised_statuses_stay_active(self):
        """
        "Detected" and "Under review" are open, and so is anything unrecognised.

        Staying active is the safe direction to be wrong in.
        """
        for status in ("Detected", "Under review", "Something new", "", "detected"):
            with self.subTest(status=status):
                findings = self.parse_string(self.issue(lifecycle=status))
                self.assertTrue(findings[0].active)
                self.assertFalse(findings[0].is_mitigated)
                self.assertFalse(findings[0].out_of_scope)

    def test_status_matching_ignores_case(self):
        for status, flag in (("solved", "is_mitigated"), ("SOLVED", "is_mitigated"),
                             ("false positive", "false_p"), ("Ignored", "out_of_scope")):
            with self.subTest(status=status):
                findings = self.parse_string(self.issue(lifecycle=status))
                self.assertFalse(findings[0].active)
                self.assertTrue(getattr(findings[0], flag))

    def test_a_host_shaped_asset_becomes_an_endpoint(self):
        finding = self.by_uid("groupib_many_vuln.json")["issue-0006"]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("files.example.com", locations[0].host)
        self.assertIsNone(finding.component_name)

    def test_an_address_with_a_port_becomes_an_endpoint_with_that_port(self):
        """
        Group-IB sends a bare host or address with no scheme.

        The connector prefixes "//" so DefectDojo reads it as an authority rather than a path; building
        the endpoint from its parts reaches the same result without the string trick.
        """
        finding = self.by_uid("groupib_many_vuln.json")["issue-0002"]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("10.20.0.11", locations[0].host)
        self.assertEqual(8443, locations[0].port)

    def test_a_url_asset_keeps_its_scheme_and_path_is_not_the_host(self):
        finding = self.by_uid("groupib_many_vuln.json")["issue-0004"]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("www.example.com", locations[0].host)
        self.assertEqual("https", locations[0].protocol)

    def test_an_asset_that_is_not_host_shaped_becomes_the_component(self):
        """
        Group-IB reports software names and SSL descriptors in the same field as hosts.

        Recording a software name as an endpoint would make Endpoint.clean() raise and fail the whole
        import, so it becomes the component instead - and is not lost.
        """
        finding = self.by_uid("groupib_many_vuln.json")["issue-0003"]
        self.assertEqual("OpenSSL 1.0.2k", finding.component_name)
        self.assertEqual(0, len(self.get_unsaved_locations(finding)))

    def test_asset_shapes(self):
        host_shaped = ("app.example.com", "10.20.0.11", "10.20.0.11:8443",
                       "https://app.example.com/x", "//app.example.com")
        not_host_shaped = ("OpenSSL 1.0.2", "SSL certificate expiry", "no-dot-here",
                           "path/like/value", "1.2.3.999999")
        for asset in host_shaped:
            with self.subTest(asset=asset, shape="host"):
                findings = self.parse_string(self.issue(asset=asset))
                self.assertEqual(1, len(self.get_unsaved_locations(findings[0])),
                                 f"{asset} should be an endpoint")
        for asset in not_host_shaped:
            with self.subTest(asset=asset, shape="component"):
                findings = self.parse_string(self.issue(asset=asset))
                self.assertEqual(0, len(self.get_unsaved_locations(findings[0])),
                                 f"{asset} should not be an endpoint")
                self.assertEqual(asset, findings[0].component_name)

    def test_an_empty_asset_records_neither(self):
        finding = self.by_uid("groupib_many_vuln.json")["issue-0005"]
        self.assertIsNone(finding.component_name)
        self.assertEqual(0, len(self.get_unsaved_locations(finding)))

    def test_the_title_falls_back_through_the_reason_and_the_category(self):
        findings = self.by_uid("groupib_many_vuln.json")
        self.assertEqual("A login form was found on a marketing host", findings["issue-0004"].title)
        self.assertEqual("Group-IB ASM issue issue-0005", findings["issue-0005"].title)

    def test_an_issue_with_no_details_says_so(self):
        """An empty description would read as though the data had been lost in transit."""
        finding = self.by_uid("groupib_many_vuln.json")["issue-0005"]
        self.assertEqual("No additional details were provided by Group-IB ASM.", finding.description)

    def test_mitre_techniques_become_sorted_tags(self):
        """Group-IB sends them as a MAP keyed by technique, so the sort is what makes them stable."""
        finding = self.by_uid("groupib_many_vuln.json")["issue-0001"]
        self.assertEqual(["mitre-attack:T1190", "mitre-attack:T1595"], finding.unsaved_tags)

    def test_an_empty_mitre_map_produces_no_tags(self):
        findings = self.by_uid("groupib_many_vuln.json")
        self.assertIsNone(findings["issue-0006"].unsaved_tags)
        self.assertIsNone(findings["issue-0002"].unsaved_tags)

    def test_an_unparseable_first_seen_leaves_the_date_alone(self):
        finding = self.by_uid("groupib_many_vuln.json")["issue-0005"]
        self.assertEqual(datetime.now(tz=UTC).date(), finding.date)

    def test_export_shapes(self):
        issue = {"id": "issue-1", "status": "Detected",
                 "body": {"type": "An issue", "status": "Low severity"}}
        for payload in ([issue], {"items": [issue]}, {"data": [issue]}, {"results": [issue]},
                        {"issues": [issue]}):
            with self.subTest(shape=str(payload)[:20]):
                self.assertEqual(1, len(self.parse_string(payload)))

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("Group-IB", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("items", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"items": [
            "not an object",
            None,
            {"id": "issue-9", "status": "Detected", "body": "not an object"},
            {"id": "issue-8", "status": "Detected",
             "body": {"type": "An issue", "status": "Low severity",
                      "alertMitreInfo": "not a map"}},
        ]})
        self.assertEqual(2, len(findings))
        by_uid = {finding.unique_id_from_tool: finding for finding in findings}
        # A row with no usable body still becomes a finding, titled after its id.
        self.assertEqual("Group-IB ASM issue issue-9", by_uid["issue-9"].title)
        self.assertIsNone(by_uid["issue-8"].unsaved_tags)

    def test_the_hash_is_only_the_title_and_severity(self):
        """An ASM issue has neither a file nor a package to hash."""
        self.assertEqual(["title", "severity"], GroupibParser().get_dedupe_fields())

    def test_severity_is_always_a_known_value(self):
        for filename in ("groupib_many_vuln.json", "groupib_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
