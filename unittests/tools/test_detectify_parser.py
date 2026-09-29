import io
import json
from datetime import date

from dojo.models import Finding, Test
from dojo.tools.detectify.parser import DetectifyParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDetectifyParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("detectify") / filename).open(encoding="utf-8") as file:
            return list(DetectifyParser().get_findings(file, Test()))

    def by_uid(self, filename):
        return {f.unique_id_from_tool: f for f in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Detectify connector's ScanType() verbatim.

        Note it does NOT follow the "<Vendor> - Connectors Import" pattern the other connector scan
        types use, so it cannot be derived - it has to be copied. Any drift and a customer who
        uploads an export and also syncs the API gets two un-deduplicated copies of every finding.
        """
        parser = DetectifyParser()
        self.assertEqual(["Detectify Scan"], parser.get_scan_types())
        self.assertEqual("Detectify Scan", parser.get_label_for_scan_types("Detectify Scan"))
        self.assertNotIn("Detectify - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("detectify_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("detectify_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's finding_converter."""
        findings = self.parse("detectify_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Remote code execution via CVE-2000-0001", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("00000000-0000-4000-8000-000000000001", finding.unique_id_from_tool)
        # vuln_id_from_tool is the definition's title, Detectify's stable rule name.
        self.assertEqual("Insecure Deserialization", finding.vuln_id_from_tool)
        self.assertEqual(502, finding.cwe)
        self.assertEqual(date(2026, 7, 1), finding.date)
        self.assertTrue(finding.active)
        # Detectify is EASM/DAST.
        self.assertFalse(finding.static_finding)
        self.assertTrue(finding.dynamic_finding)

        self.assertIn("**Host:** app.example.com", finding.description)
        self.assertIn("**Location:** /api/upload", finding.description)
        self.assertIn("**Scan source:** surface-monitoring", finding.description)
        self.assertIn("**Status:** active", finding.description)
        self.assertIn("The endpoint deserializes untrusted input.", finding.description)
        # The definition's risk text becomes the impact.
        self.assertEqual("An attacker can execute arbitrary code on the host.", finding.impact)
        self.assertEqual(["production", "external", "surface-monitoring"], finding.unsaved_tags)

    def test_the_cvss_31_block_is_preferred_over_30_and_20_is_ignored(self):
        """
        Detectify reports 2.0, 3.0 and 3.1 blocks. Finding.cvssv3 is a v3 field.

        Taking 2.0 would put a v2 vector in a v3 field, and taking 3.0 over 3.1 would report a stale
        score - the fixture deliberately gives all three different values.
        """
        finding = self.parse("detectify_one_vuln.json")[0]
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", finding.cvssv3)

    def test_a_block_with_only_a_vector_still_counts_as_present(self):
        """A zero score with a vector is real data; requiring a score would discard the vector."""
        finding = self.by_uid("detectify_many_vuln.json")["00000000-0000-4000-8000-000000000002"]
        self.assertEqual("CVSS:3.0/AV:N/AC:H", finding.cvssv3)
        self.assertIsNone(finding.cvssv3_score)

    def test_a_block_with_only_a_score_still_counts_as_present(self):
        finding = self.by_uid("detectify_many_vuln.json")["00000000-0000-4000-8000-000000000006"]
        self.assertEqual(3.1, finding.cvssv3_score)
        self.assertIsNone(finding.cvssv3)

    def test_the_cvss_preference_directly(self):
        parser = DetectifyParser()
        self.assertEqual((9.8, "v31"), parser.cvss({
            "cvss_2_0": {"score": 9.0, "vector": "v20"},
            "cvss_3_0": {"score": 9.5, "vector": "v30"},
            "cvss_3_1": {"score": 9.8, "vector": "v31"},
        }))
        self.assertEqual((9.5, "v30"), parser.cvss({"cvss_3_0": {"score": 9.5, "vector": "v30"}}))
        # A 2.0-only report yields nothing, because it cannot go in a v3 field.
        self.assertEqual((0, ""), parser.cvss({"cvss_2_0": {"score": 9.0, "vector": "v20"}}))
        self.assertEqual((0, ""), parser.cvss(None))

    def test_patched_and_false_positive_findings_are_not_imported(self):
        """Importing resolved and dismissed findings would put closed work back in front of the team."""
        uids = set(self.by_uid("detectify_many_vuln.json"))
        self.assertNotIn("00000000-0000-4000-8000-000000000004", uids)  # patched
        self.assertNotIn("00000000-0000-4000-8000-000000000005", uids)  # false_positive
        self.assertEqual(4, len(uids))

    def test_an_accepted_risk_is_imported_and_flagged_rather_than_skipped(self):
        """
        The connector deliberately keeps accepted risks, unlike patched and false-positive.

        Discarding them would lose the record that somebody accepted the risk.
        """
        finding = self.by_uid("detectify_many_vuln.json")["00000000-0000-4000-8000-000000000002"]
        self.assertTrue(finding.risk_accepted)
        self.assertTrue(finding.active)

    def test_an_ordinary_finding_is_not_flagged_risk_accepted(self):
        finding = self.parse("detectify_one_vuln.json")[0]
        self.assertFalse(finding.risk_accepted)

    def test_the_ignored_status_check_directly(self):
        parser = DetectifyParser()
        for status in ("patched", "false_positive", "PATCHED", " false_positive "):
            self.assertTrue(parser.is_ignored({"status": status}), status)
        for status in ("active", "accepted_risk", "", None):
            self.assertFalse(parser.is_ignored({"status": status}), status)

    def test_information_is_one_of_detectifys_severity_spellings(self):
        finding = self.by_uid("detectify_many_vuln.json")["00000000-0000-4000-8000-000000000002"]
        self.assertEqual("Info", finding.severity)

    def test_the_severity_mapping_directly(self):
        parser = DetectifyParser()
        for raw, expected in [
            ("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low"),
            ("information", "Info"), ("info", "Info"), ("informational", "Info"),
            ("CRITICAL", "Critical"), ("not-a-severity", "Info"), ("", "Info"),
        ]:
            finding = parser.build_finding({"uuid": "u", "severity": raw}, Test())
            self.assertEqual(expected, finding.severity, raw)

    def test_cves_are_extracted_from_prose_including_the_references(self):
        """
        Detectify has no dedicated CVE field, so the connector scans several text fields.

        The fixture puts one CVE in the title and a different one in a reference name, to prove both
        are picked up and that they are deduplicated in order.
        """
        finding = self.parse("detectify_one_vuln.json")[0]
        self.assertEqual(["CVE-2000-0001", "CVE-2000-0002"], finding.unsaved_vulnerability_ids)

    def test_a_finding_with_no_cve_anywhere_has_none(self):
        finding = self.by_uid("detectify_many_vuln.json")["00000000-0000-4000-8000-000000000006"]
        self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_references_render_name_and_link_and_either_alone(self):
        finding = self.parse("detectify_one_vuln.json")[0]
        self.assertEqual(
            "- Advisory CVE-2000-0002: https://example.com/advisories/cve-2000-0001\n"
            "- https://example.com/guidance\n"
            "- Vendor bulletin",
            finding.references,
        )

    def test_the_mitigation_points_at_the_reference_links(self):
        """Detectify supplies no remediation text, only links, so the connector points at them."""
        finding = self.parse("detectify_one_vuln.json")[0]
        self.assertEqual(
            "See references:\n"
            "https://example.com/advisories/cve-2000-0001\n"
            "https://example.com/guidance",
            finding.mitigation,
        )

    def test_a_finding_with_no_references_has_no_mitigation(self):
        finding = self.by_uid("detectify_many_vuln.json")["00000000-0000-4000-8000-000000000002"]
        self.assertIsNone(finding.mitigation)
        self.assertIsNone(finding.references)

    def test_the_request_url_is_preferred_for_the_endpoint(self):
        """
        Preference order: the request URL, then host plus path, then the location alone.

        Asserted through get_unsaved_locations so this passes in both V3_FEATURE_LOCATIONS modes.
        """
        finding = self.parse("detectify_one_vuln.json")[0]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("app.example.com", locations[0].host)
        self.assertEqual("https", locations[0].protocol)

    def test_the_host_and_path_are_combined_when_there_is_no_request(self):
        finding = self.by_uid("detectify_many_vuln.json")["00000000-0000-4000-8000-000000000002"]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("shop.example.com", locations[0].host)
        self.assertIn("checkout", locations[0].path)

    def test_a_location_that_is_not_a_path_is_not_appended_to_the_host(self):
        """
        The location is only appended when it starts with "/".

        Otherwise it is not a path and concatenating it would produce a nonsense host.

        Asserted as falsey rather than None: an unset path is "" on the URL location model
        (CharField(blank=True)) and None on Endpoint, so asserting either one specifically passes
        under one value of V3_FEATURE_LOCATIONS and fails under the other.
        """
        finding = self.by_uid("detectify_many_vuln.json")["00000000-0000-4000-8000-000000000006"]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("api.example.com", locations[0].host)
        self.assertFalse(locations[0].path)

    def test_a_full_url_location_is_used_when_there_is_no_host(self):
        finding = self.by_uid("detectify_many_vuln.json")["00000000-0000-4000-8000-000000000003"]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("legacy.example.com", locations[0].host)

    def test_a_finding_with_no_title_or_definition_is_named_from_its_uuid(self):
        finding = self.by_uid("detectify_many_vuln.json")["00000000-0000-4000-8000-000000000003"]
        self.assertEqual(
            "Detectify finding 00000000-0000-4000-8000-000000000003", finding.title,
        )
        self.assertIsNone(finding.vuln_id_from_tool)
        self.assertIsNone(finding.impact)

    def test_a_finding_with_no_title_falls_back_to_the_definition_title(self):
        finding = self.by_uid("detectify_many_vuln.json")["00000000-0000-4000-8000-000000000002"]
        self.assertEqual("Information Disclosure", finding.title)

    def test_an_unparseable_timestamp_leaves_the_date_unset(self):
        finding = self.by_uid("detectify_many_vuln.json")["00000000-0000-4000-8000-000000000003"]
        self.assertIsNone(finding.date)

    def test_an_empty_tag_name_is_dropped(self):
        finding = self.by_uid("detectify_many_vuln.json")["00000000-0000-4000-8000-000000000003"]
        self.assertEqual([], finding.unsaved_tags)

    def test_a_bare_array_is_accepted(self):
        report = io.StringIO(json.dumps([{
            "uuid": "u1", "title": "A finding", "severity": "high", "status": "active",
            "host": "app.example.com",
        }]))
        findings = list(DetectifyParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("High", findings[0].severity)

    def test_a_repeated_uuid_collapses(self):
        row = {"uuid": "same", "title": "A finding", "severity": "high", "status": "active"}
        report = io.StringIO(json.dumps({"vulnerabilities": [row, row]}))
        self.assertEqual(1, len(list(DetectifyParser().get_findings(report, Test()))))

    def test_an_unexpected_shape_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(DetectifyParser().get_findings(io.StringIO('"nope"'), Test()))
        self.assertIn("vulnerabilities", str(raised.exception))
