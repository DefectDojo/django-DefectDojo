import io
import json
from datetime import UTC, date, datetime

from dojo.models import Finding, Test
from dojo.tools.vmanplus.parser import VmanplusParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestVmanplusParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("vmanplus") / filename
        with path.open(encoding="utf-8") as file:
            return list(VmanplusParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(VmanplusParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def row(self, **overrides):
        row = {"resource_id": "301", "resource_name": "generic-host-01",
               "vulnerabilityid": "50123", "vulnerabilityname": "A vulnerability",
               "severity": "Important", "vulnerability_status": "Open"}
        row.update(overrides)
        return {"vulnerabilities": [row]}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the VMP connector's ScanTypeName verbatim.

        Note it does NOT follow the "<Vendor> - Connectors Import" pattern the other connector scan
        types use, so it cannot be derived - it has to be copied.
        """
        parser = VmanplusParser()
        self.assertEqual(["ManageEngine Vulnerability Manager Plus Scan"], parser.get_scan_types())
        self.assertEqual("ManageEngine Vulnerability Manager Plus Scan",
                         parser.get_label_for_scan_types("ManageEngine Vulnerability Manager Plus Scan"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("vmanplus_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("vmanplus_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's finding_converter."""
        findings = self.parse("vmanplus_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Remote code execution in the example office suite", finding.title)
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("vmanplus-301-50123", finding.unique_id_from_tool)
        self.assertEqual("50123", finding.vuln_id_from_tool)
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual(8.8, finding.cvssv3_score)
        self.assertEqual("generic-host-01", finding.component_name)
        self.assertEqual("https://example.com/advisories/CVE-2000-0001", finding.references)
        self.assertEqual(date(2024, 6, 2), finding.date)
        self.assertTrue(finding.active)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(
            "**Patch:** Example Office Suite security update 2024-06\n**Patch ID:** 77001",
            finding.mitigation,
        )
        self.assertEqual(
            "**Vulnerability:** Remote code execution in the example office suite\n"
            "**CVE IDs:** CVE-2000-0001\n"
            "**Host:** generic-host-01\n"
            "**IP address:** 10.20.0.11\n"
            "**Status:** Open",
            finding.description,
        )

    def test_many_vuln(self):
        self.assertEqual(4, len(self.parse("vmanplus_many_vuln.json")))

    def test_the_msrc_severity_names_do_not_mean_what_they_say(self):
        """
        VMP grades on Microsoft's scale: "Important" is High and "Moderate" is Medium.

        DefectDojo has neither name, so reading them literally would fall through to Info and drop
        both a tier.
        """
        findings = self.by_uid("vmanplus_many_vuln.json")
        self.assertEqual("High", findings["vmanplus-301-50123"].severity)
        self.assertEqual("Medium", findings["vmanplus-302-50124"].severity)

    def test_severity_words(self):
        for label, expected in (("Critical", "Critical"), ("Important", "High"), ("High", "High"),
                                ("Moderate", "Medium"), ("Medium", "Medium"), ("Low", "Low"),
                                ("Unrated", "Info"), ("", "Info"), ("IMPORTANT", "High")):
            with self.subTest(label=label):
                findings = self.parse_string(self.row(severity=label))
                self.assertEqual(expected, findings[0].severity)

    def test_the_cvss_v3_score_wins_and_v2_is_the_fallback(self):
        """VMP reports both for older advisories, and v3 is the one to prefer."""
        findings = self.by_uid("vmanplus_many_vuln.json")
        self.assertEqual(8.8, findings["vmanplus-301-50123"].cvssv3_score)
        # v3 is zero here, so the v2 score is used.
        self.assertEqual(6.8, findings["vmanplus-302-50124"].cvssv3_score)
        self.assertEqual(0.0, findings["vmanplus-303-50125"].cvssv3_score)

    def test_a_closed_or_fixed_vulnerability_is_inactive(self):
        findings = self.by_uid("vmanplus_many_vuln.json")
        self.assertFalse(findings["vmanplus-302-50124"].active)
        self.assertFalse(findings["vmanplus-304-50126"].active)
        self.assertTrue(findings["vmanplus-301-50123"].active)

    def test_status_matching_ignores_case(self):
        for status, active in (("Closed", False), ("close", False), ("FIXED", False),
                               ("Remediated", False), ("Open", True), ("Mitigated", True),
                               ("", True)):
            with self.subTest(status=status):
                findings = self.parse_string(self.row(vulnerability_status=status))
                self.assertEqual(active, findings[0].active)

    def test_an_unfamiliar_status_stays_active(self):
        """
        "Mitigated" is not one of the four closing states, so it stays open.

        Treating an unfamiliar status as closed would silently hide a live vulnerability.
        """
        finding = self.by_uid("vmanplus_many_vuln.json")["vmanplus-303-50125"]
        self.assertTrue(finding.active)
        self.assertIn("**Status:** Mitigated", finding.description)

    def test_the_host_is_the_component_not_a_package(self):
        """The same vulnerability on two machines stays two findings - two machines to patch."""
        self.assertEqual(["title", "severity", "component_name"],
                         VmanplusParser().get_dedupe_fields())
        findings = self.by_uid("vmanplus_many_vuln.json")
        self.assertEqual("generic-host-01", findings["vmanplus-301-50123"].component_name)

    def test_the_host_falls_back_to_the_fqdn_then_the_address(self):
        findings = self.by_uid("vmanplus_many_vuln.json")
        self.assertEqual("generic-host-02.corp.example.com",
                         findings["vmanplus-302-50124"].component_name)
        self.assertEqual("10.20.0.13", findings["vmanplus-303-50125"].component_name)

    def test_the_title_falls_back_to_the_cve_ids_then_the_vulnerability_id(self):
        findings = self.by_uid("vmanplus_many_vuln.json")
        self.assertEqual("CVE-2000-0004", findings["vmanplus-303-50125"].title)
        self.assertEqual("ManageEngine VMP vulnerability 50126",
                         findings["vmanplus-304-50126"].title)

    def test_several_cve_ids_arrive_in_one_string_and_are_extracted_and_sorted(self):
        """
        VMP sends every CVE for a vulnerability in ONE field, so they are extracted rather than used
        whole.

        The connector's shared extractor sorts its results, so the order is alphabetical rather than
        the order they appear - the fixture names CVE-2000-0002 first.
        """
        finding = self.by_uid("vmanplus_many_vuln.json")["vmanplus-301-50123"]
        self.assertEqual(["CVE-2000-0001", "CVE-2000-0002"], finding.unsaved_vulnerability_ids)
        # The raw field is still shown as VMP wrote it.
        self.assertIn("**CVE IDs:** CVE-2000-0002, CVE-2000-0001", finding.description)

    def test_a_row_with_no_cve_ids_has_none(self):
        finding = self.by_uid("vmanplus_many_vuln.json")["vmanplus-304-50126"]
        self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_ids_sent_as_numbers_render_without_a_decimal_point(self):
        """
        VMP's ids are strings that its own decoder also accepts as numbers.

        An id read as a float would render as "50124.0" and never match the API's "50124".
        """
        findings = self.by_uid("vmanplus_many_vuln.json")
        self.assertIn("vmanplus-302-50124", findings)
        self.assertEqual("50124", findings["vmanplus-302-50124"].vuln_id_from_tool)

    def test_timestamps_are_epoch_milliseconds(self):
        """Reading them as seconds would date every finding to 1970."""
        findings = self.by_uid("vmanplus_many_vuln.json")
        self.assertEqual(date(2024, 6, 2), findings["vmanplus-301-50123"].date)
        self.assertEqual(date(2024, 6, 3), findings["vmanplus-302-50124"].date)

    def test_a_zero_or_absent_timestamp_leaves_the_date_alone(self):
        findings = self.by_uid("vmanplus_many_vuln.json")
        self.assertEqual(datetime.now(tz=UTC).date(), findings["vmanplus-303-50125"].date)
        self.assertEqual(datetime.now(tz=UTC).date(), findings["vmanplus-304-50126"].date)

    def test_a_row_with_no_patch_leaves_the_mitigation_unset(self):
        findings = self.by_uid("vmanplus_many_vuln.json")
        self.assertIsNone(findings["vmanplus-302-50124"].mitigation)
        self.assertIn("**Patch ID:** 77001", findings["vmanplus-301-50123"].mitigation)

    def test_export_shapes(self):
        row = {"resource_id": "301", "vulnerabilityid": "50123",
               "vulnerabilityname": "A vulnerability", "severity": "Low"}
        for payload in ([row], {"vulnerabilities": [row]}, {"data": [row]}, {"results": [row]}):
            with self.subTest(shape=str(payload)[:24]):
                self.assertEqual(1, len(self.parse_string(payload)))

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("ManageEngine", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("vulnerabilities", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"vulnerabilities": [
            "not an object",
            None,
            {"resource_id": "309", "vulnerabilityid": "50129",
             "vulnerabilityname": "A vulnerability", "severity": "Low"},
        ]})
        self.assertEqual(1, len(findings))
        self.assertEqual("vmanplus-309-50129", findings[0].unique_id_from_tool)

    def test_severity_is_always_a_known_value(self):
        for filename in ("vmanplus_many_vuln.json", "vmanplus_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
