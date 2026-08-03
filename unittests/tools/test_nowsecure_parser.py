import io
import json
from datetime import UTC, datetime

from dojo.models import Finding, Test
from dojo.tools.nowsecure.parser import NowSecureParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestNowSecureParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("nowsecure") / filename).open(encoding="utf-8") as file:
            return list(NowSecureParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(NowSecureParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def row(self, **overrides):
        row = {"affected": True, "hidden": False, "title": "A finding", "severity": "high",
               "check_id": "a_check", "analysis_type": "static"}
        row.update(overrides)
        return {"findings": [row]}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the NowSecure connector's ScanTypeName verbatim - just "NowSecure".

        It does NOT follow the "<Vendor> - Connectors Import" pattern, so it cannot be derived; any
        drift and someone who uploads an export and also syncs the API gets two un-deduplicated
        copies of every finding.
        """
        parser = NowSecureParser()
        self.assertEqual(["NowSecure"], parser.get_scan_types())
        self.assertEqual("NowSecure", parser.get_label_for_scan_types("NowSecure"))
        self.assertNotIn("NowSecure - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        """
        NowSecure reports every check it ran, including the ones that found nothing.

        A check that does not affect the app is not a finding, and one hidden in NowSecure has been
        suppressed there - importing either would put noise in front of the team.
        """
        self.assertEqual(0, len(self.parse("nowsecure_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("nowsecure_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's finding_converter."""
        findings = self.parse("nowsecure_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("World-readable files created by the app", finding.title)
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("nowsecure-insecure_data_storage_world_readable-12345", finding.unique_id_from_tool)
        self.assertEqual("insecure_data_storage_world_readable", finding.vuln_id_from_tool)
        self.assertEqual(7.5, finding.cvssv3_score)
        self.assertEqual("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", finding.cvssv3)
        self.assertEqual("Use MODE_PRIVATE when opening files.", finding.mitigation)
        self.assertEqual(datetime(2024, 7, 1, tzinfo=UTC).date(), finding.date)
        self.assertTrue(finding.active)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(["Data Storage", "static", "android"], finding.unsaved_tags)

        self.assertEqual(
            "**Category:** Data Storage\n"
            "**Check:** insecure_data_storage_world_readable\n"
            "**Analysis:** static\n\n"
            "**Description:**\n"
            "The app writes files that any other app on the device can read.\n\n"
            "**Detail:**\n"
            "Observed mode 0644 on two files under the app's data directory.",
            finding.description,
        )

    def test_many_vuln(self):
        """Five checks reported, two of them not findings."""
        self.assertEqual(3, len(self.parse("nowsecure_many_vuln.json")))

    def test_a_check_that_does_not_affect_the_app_is_skipped(self):
        for affected, hidden, imported in ((True, False, 1), (False, False, 0), (True, True, 0),
                                           (False, True, 0)):
            with self.subTest(affected=affected, hidden=hidden):
                findings = self.parse_string(self.row(affected=affected, hidden=hidden))
                self.assertEqual(imported, len(findings))

    def test_static_and_dynamic_are_decided_per_finding(self):
        """
        One assessment runs both analyses of the same app, so the file cannot decide this.

        An analysis type the connector does not recognise leaves both flags alone - which is NOT
        neutral, because DefectDojo defaults static_finding to False and dynamic_finding to TRUE. Such
        a finding is therefore recorded as dynamic, exactly as the connector's own findings are.
        Setting two Falses instead would make a file import and an API sync disagree.
        """
        findings = self.by_uid("nowsecure_many_vuln.json")

        static = findings["nowsecure-insecure_data_storage_world_readable-12345"]
        self.assertTrue(static.static_finding)
        self.assertFalse(static.dynamic_finding)

        dynamic = findings["nowsecure-tls_certificate_validation_disabled-12346"]
        self.assertFalse(dynamic.static_finding)
        self.assertTrue(dynamic.dynamic_finding)

        unknown = findings["nowsecure-debug-symbols-present-in-the-binary"]
        self.assertFalse(unknown.static_finding)
        self.assertTrue(unknown.dynamic_finding)

    def test_severity_labels(self):
        for label, expected in (("critical", "Critical"), ("high", "High"), ("medium", "Medium"),
                                ("low", "Low"), ("info", "Info"), ("informational", "Info"),
                                ("", "Info"), ("HIGH", "High"), ("not a label", "Info")):
            with self.subTest(label=label):
                findings = self.parse_string(self.row(severity=label))
                self.assertEqual(expected, findings[0].severity)

    def test_the_unique_id_slugs_the_title_when_there_is_no_check_id(self):
        """
        Something stable is needed for the identity, and without a check id the title is all there is.

        Note the vulnerability id is omitted when it is zero, which is how NowSecure says it has none.
        """
        findings = self.by_uid("nowsecure_many_vuln.json")
        self.assertIn("nowsecure-debug-symbols-present-in-the-binary", findings)

    def test_the_vulnerability_id_distinguishes_two_hits_of_one_check(self):
        findings = self.parse_string({"findings": [
            {"affected": True, "title": "A finding", "severity": "high", "check_id": "a_check",
             "unique_vulnerability_id": 1},
            {"affected": True, "title": "A finding", "severity": "high", "check_id": "a_check",
             "unique_vulnerability_id": 2},
        ]})
        self.assertEqual(
            {"nowsecure-a_check-1", "nowsecure-a_check-2"},
            {finding.unique_id_from_tool for finding in findings},
        )

    def test_title_falls_back_to_the_check_then_to_a_constant(self):
        by_check = self.parse_string(self.row(title="", check_id="a_check"))
        self.assertEqual("NowSecure: a_check", by_check[0].title)

        bare = self.parse_string(self.row(title="", check_id=""))
        self.assertEqual("NowSecure finding", bare[0].title)
        self.assertIsNone(bare[0].vuln_id_from_tool)

    def test_identifiers_are_sorted_and_deduplicated_case_insensitively(self):
        """
        NowSecure's extractor sorts and drops case-insensitive duplicates, unlike the order-preserving
        path other connectors use. Mirrored so the two import paths agree on the same export.
        """
        finding = self.by_uid("nowsecure_many_vuln.json")["nowsecure-tls_certificate_validation_disabled-12346"]
        self.assertEqual(["CVE-2000-0001", "CVE-2000-0002"], finding.unsaved_vulnerability_ids)

    def test_a_finding_with_no_identifiers_has_none(self):
        finding = self.by_uid("nowsecure_many_vuln.json")["nowsecure-insecure_data_storage_world_readable-12345"]
        self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_an_unscored_finding_lands_as_zero(self):
        """
        The connector sets the score unconditionally, so an unscored finding gets 0.0.

        Mirrored for parity rather than left unset; raised in the PR as a follow-up for both sides.
        """
        finding = self.by_uid("nowsecure_many_vuln.json")["nowsecure-debug-symbols-present-in-the-binary"]
        self.assertEqual(0.0, finding.cvssv3_score)
        self.assertIsNone(finding.cvssv3)

    def test_no_recommendation_leaves_the_mitigation_empty(self):
        finding = self.by_uid("nowsecure_many_vuln.json")["nowsecure-debug-symbols-present-in-the-binary"]
        self.assertEqual("", finding.mitigation)

    def test_a_finding_with_no_prose_has_only_the_field_lines(self):
        finding = self.by_uid("nowsecure_many_vuln.json")["nowsecure-debug-symbols-present-in-the-binary"]
        self.assertEqual(
            "**Category:** Code Quality\n**Analysis:** manual_review",
            finding.description,
        )

    def test_the_assessment_supplies_the_date_and_the_platform(self):
        """
        Neither is on the finding: NowSecure puts them on the assessment that produced it.

        Without the assessment the findings still import, just without a date or a platform tag.
        """
        findings = self.parse_string({"findings": [
            {"affected": True, "title": "A finding", "severity": "high", "check_id": "a_check",
             "category": "Network", "analysis_type": "static"},
        ]})
        self.assertEqual(datetime.now(tz=UTC).date(), findings[0].date)
        self.assertEqual(["Network", "static"], findings[0].unsaved_tags)

    def test_a_bare_array_of_findings_is_accepted(self):
        """NowSecure's findings endpoint answers with a bare array."""
        findings = self.parse_string([
            {"affected": True, "title": "A finding", "severity": "high", "check_id": "a_check"},
        ])
        self.assertEqual(1, len(findings))
        self.assertEqual("A finding", findings[0].title)

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("NowSecure", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("findings", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"findings": [
            "not an object",
            None,
            {"affected": True, "title": "A finding", "severity": "high", "check_id": "a_check"},
        ]})
        self.assertEqual(1, len(findings))

    def test_severity_is_always_a_known_value(self):
        for filename in ("nowsecure_many_vuln.json", "nowsecure_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
