import io
import json
from datetime import UTC, date, datetime

from dojo.models import Finding, Test
from dojo.tools.bigid.parser import BigidParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestBigidParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("bigid") / filename
        with path.open(encoding="utf-8") as file:
            return list(BigidParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(BigidParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def row(self, **overrides):
        row = {"caseId": "case-1", "caseLabel": "A case", "policyName": "A policy",
               "severityLevel": "high", "caseStatus": "open", "dataSourceName": "generic-source"}
        row.update(overrides)
        return {"cases": [row]}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the BigID connector's ScanTypeName verbatim.

        Note it does NOT follow the "<Vendor> - Connectors Import" pattern the other connector scan
        types use, so it cannot be derived - it has to be copied.
        """
        parser = BigidParser()
        self.assertEqual(["BigID Scan"], parser.get_scan_types())
        self.assertEqual("BigID Scan", parser.get_label_for_scan_types("BigID Scan"))
        self.assertNotIn("BigID - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("bigid_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("bigid_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's finding_converter."""
        findings = self.parse("bigid_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Unprotected personal data in a reporting database", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("bigid-case-0001", finding.unique_id_from_tool)
        self.assertEqual("case-0001", finding.vuln_id_from_tool)
        self.assertEqual("reporting-db", finding.component_name)
        self.assertEqual("Move the data to an approved store and revoke the broad read grant.",
                         finding.mitigation)
        self.assertEqual(date(2024, 6, 2), finding.date)
        self.assertTrue(finding.active)
        self.assertFalse(finding.is_mitigated)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(["PostgreSQL", "Restricted"], finding.unsaved_tags)

        self.assertEqual(
            "**Policy:** Personal data outside an approved store\n"
            "**Policy description:** Personal data must only live in an approved, "
            "access-controlled store.\n"
            "**Data source:** reporting-db\n"
            "**Data source type:** PostgreSQL\n"
            "**Sensitivity:** Restricted\n"
            "**Affected objects:** 412\n"
            "**Status:** open\n"
            "**Assignee:** data-owner",
            finding.description,
        )

    def test_many_vuln(self):
        """The row with no case id is dropped; four remain."""
        self.assertEqual(4, len(self.parse("bigid_many_vuln.json")))

    def test_only_the_count_of_affected_objects_is_read_never_the_data(self):
        """
        A BigID case is about sensitive data that was found, so the data itself is never carried.

        The fixture's case includes sample values, a preview and matched values. None of it may reach
        the finding - the count is the only thing said about the affected objects.
        """
        findings = self.parse("bigid_with_sample_values.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertIn("**Affected objects:** 9", finding.description)

        rendered = " ".join(str(value) for value in (
            finding.title, finding.description, finding.mitigation, finding.component_name,
            finding.unsaved_tags, finding.vuln_id_from_tool, finding.unique_id_from_tool,
        ))
        self.assertNotIn("placeholder-not-real-data", rendered)
        for field in ("sampleValues", "preview", "matchedValues", "objectDetails"):
            self.assertNotIn(field, rendered)

    def test_export_shapes(self):
        """
        BigID's own samples disagree about the shape, so its client accepts all three.

        A bare array, a {"data": {"cases": []}} object, and a top-level {"cases": []}.
        """
        row = {"caseId": "case-1", "caseLabel": "A case", "severityLevel": "low",
               "caseStatus": "open", "dataSourceName": "generic-source"}
        for payload in ([row], {"cases": [row]}, {"data": {"cases": [row], "totalCount": 1}}):
            with self.subTest(shape=str(payload)[:24]):
                self.assertEqual(1, len(self.parse_string(payload)))

    def test_the_wrapped_form_wins_over_a_top_level_list(self):
        """The client prefers data.cases whenever it carries anything, so the parser does too."""
        wrapped = {"caseId": "wrapped", "caseLabel": "Wrapped", "severityLevel": "low",
                   "caseStatus": "open"}
        top = {"caseId": "top-level", "caseLabel": "Top level", "severityLevel": "low",
               "caseStatus": "open"}
        findings = self.parse_string({"data": {"cases": [wrapped], "totalCount": 1}, "cases": [top]})
        self.assertEqual(1, len(findings))
        self.assertEqual("bigid-wrapped", findings[0].unique_id_from_tool)

    def test_an_empty_wrapped_form_still_reports_no_findings(self):
        """A wrapped envelope that is genuinely empty is an empty result, not a fall-through."""
        self.assertEqual(0, len(self.parse_string({"data": {"cases": [], "totalCount": 0}})))

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("BigID", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("cases", str(context.exception))

    def test_severity_labels(self):
        """BigID has no Info tier of its own, so anything unrecognised lands there."""
        for label, expected in (("critical", "Critical"), ("high", "High"), ("medium", "Medium"),
                                ("low", "Low"), ("HIGH", "High"), (" low ", "Low"),
                                ("not a level", "Info"), ("", "Info")):
            with self.subTest(label=label):
                findings = self.parse_string(self.row(severityLevel=label))
                self.assertEqual(expected, findings[0].severity)

    def test_the_title_falls_back_to_the_policy_then_the_case_id(self):
        findings = self.by_uid("bigid_many_vuln.json")
        self.assertEqual("Payment data in an object store", findings["bigid-case-0002"].title)
        self.assertEqual("BigID case case-0003", findings["bigid-case-0003"].title)

    def test_a_resolved_or_remediated_case_is_mitigated_and_inactive(self):
        findings = self.by_uid("bigid_many_vuln.json")
        for uid in ("bigid-case-0002", "bigid-case-0003"):
            with self.subTest(uid=uid):
                self.assertFalse(findings[uid].active)
                self.assertTrue(findings[uid].is_mitigated)

    def test_case_status_matching_ignores_case(self):
        """The fixture spells one status "RESOLVED"; BigID's own casing varies."""
        for status, active in (("resolved", False), ("RESOLVED", False), ("Remediated", False),
                               ("closed", False), ("open", True), ("in review", True), ("", True)):
            with self.subTest(status=status):
                findings = self.parse_string(self.row(caseStatus=status))
                self.assertEqual(active, findings[0].active)
                self.assertEqual(not active, findings[0].is_mitigated)

    def test_an_unfamiliar_status_stays_active(self):
        """
        Only the three states BigID uses for "dealt with" close a case.

        Treating an unfamiliar status as closed would silently hide a live exposure.
        """
        finding = self.by_uid("bigid_many_vuln.json")["bigid-case-0004"]
        self.assertTrue(finding.active)
        self.assertFalse(finding.is_mitigated)
        self.assertIn("**Status:** in review", finding.description)

    def test_a_quoted_count_is_read_and_a_zero_or_negative_one_is_omitted(self):
        findings = self.by_uid("bigid_many_vuln.json")
        self.assertIn("**Affected objects:** 37", findings["bigid-case-0002"].description)
        self.assertNotIn("**Affected objects:**", findings["bigid-case-0003"].description)
        self.assertNotIn("**Affected objects:**", findings["bigid-case-0004"].description)

    def test_a_case_with_no_id_is_dropped(self):
        """The case id is the whole identity; without one every row would collapse onto "bigid-"."""
        uids = self.by_uid("bigid_many_vuln.json")
        self.assertNotIn("bigid-", uids)
        for finding in uids.values():
            self.assertNotIn("Dropped", finding.title)

    def test_the_date_is_the_update_timestamp_then_creation(self):
        findings = self.by_uid("bigid_many_vuln.json")
        self.assertEqual(date(2024, 6, 2), findings["bigid-case-0001"].date)
        self.assertEqual(date(2024, 4, 1), findings["bigid-case-0002"].date)

    def test_a_timestamp_that_is_not_a_date_leaves_the_date_alone(self):
        """
        BigID's timestamps are snake_case while every other field is camelCase.

        A value too short to hold a date, or one that is not a date, falls through to the import
        default rather than failing the whole file.
        """
        findings = self.by_uid("bigid_many_vuln.json")
        self.assertEqual(datetime.now(tz=UTC).date(), findings["bigid-case-0003"].date)
        self.assertEqual(datetime.now(tz=UTC).date(), findings["bigid-case-0004"].date)

    def test_the_data_source_is_the_component(self):
        """The same policy failing on two data sources stays two findings."""
        self.assertEqual(["title", "severity", "component_name"], BigidParser().get_dedupe_fields())
        findings = self.by_uid("bigid_many_vuln.json")
        self.assertEqual("reporting-db", findings["bigid-case-0001"].component_name)
        self.assertEqual("generic-bucket", findings["bigid-case-0002"].component_name)
        self.assertIsNone(findings["bigid-case-0003"].component_name)

    def test_an_absent_remediation_leaves_the_mitigation_unset(self):
        findings = self.by_uid("bigid_many_vuln.json")
        self.assertIsNone(findings["bigid-case-0002"].mitigation)
        self.assertIsNone(findings["bigid-case-0003"].mitigation)

    def test_tags_are_the_data_source_type_and_sensitivity(self):
        findings = self.by_uid("bigid_many_vuln.json")
        self.assertEqual(["S3", "Confidential"], findings["bigid-case-0002"].unsaved_tags)
        self.assertEqual(["Elasticsearch"], findings["bigid-case-0004"].unsaved_tags)
        self.assertEqual([], findings["bigid-case-0003"].unsaved_tags)

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"cases": [
            "not an object",
            None,
            {"caseId": "case-9", "caseLabel": "A case", "severityLevel": "low", "caseStatus": "open"},
        ]})
        self.assertEqual(1, len(findings))
        self.assertEqual("bigid-case-9", findings[0].unique_id_from_tool)

    def test_severity_is_always_a_known_value(self):
        for filename in ("bigid_many_vuln.json", "bigid_one_vuln.json",
                         "bigid_with_sample_values.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
