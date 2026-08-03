import io
import json
from datetime import UTC, datetime

from dojo.models import Finding, Test
from dojo.tools.halosecurity.parser import HaloSecurityParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestHaloSecurityParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("halosecurity") / filename
        with path.open(encoding="utf-8") as file:
            return list(HaloSecurityParser().get_findings(file, Test()))

    def by_uid(self, filename):
        return {f.unique_id_from_tool: f for f in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Halo Security connector's ScanType() verbatim.

        Any drift and a customer who uploads an export and also syncs the API gets two
        un-deduplicated copies of every finding.
        """
        parser = HaloSecurityParser()
        self.assertEqual(["Halo Security - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "Halo Security - Connectors Import",
            parser.get_label_for_scan_types("Halo Security - Connectors Import"),
        )

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("halosecurity_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("halosecurity_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring RowToFinding in the connector's converter."""
        findings = self.parse("halosecurity_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("TLS certificate expires in under 14 days", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("9001:3001", finding.unique_id_from_tool)
        self.assertEqual("9001", finding.vuln_id_from_tool)
        self.assertTrue(finding.active)
        self.assertTrue(finding.verified)
        self.assertFalse(finding.static_finding)
        self.assertTrue(finding.dynamic_finding)

        # The description text only exists on the separately-fetched detail.
        self.assertIn("The certificate presented by the host expires shortly.", finding.description)
        self.assertIn("**Target:** app.example.com", finding.description)
        self.assertIn("**Halo status:** confirmed", finding.description)
        self.assertIn("**Category:** Encryption", finding.description)
        self.assertIn("**PCI:** this issue affects PCI compliance", finding.description)
        self.assertIn("**Assigned to:** Platform Team", finding.description)
        self.assertIn("**Scans since found:** 4", finding.description)

    def test_severity_is_an_integer_level_with_five_highest(self):
        """
        Halo Security grades severity as an INTEGER, 5 being the most severe - the inverse of a
        priority number.

        Treating it as a score, or assuming 1 is worst, would invert the whole ladder.
        """
        parser = HaloSecurityParser()
        for level, expected in [
            (5, "Critical"), (4, "High"), (3, "Medium"), (2, "Low"), (1, "Info"), (0, "Info"),
            (9, "Info"),
        ]:
            self.assertEqual(expected, parser.severity({"severity": level}, {}), level)

    def test_the_severity_falls_back_to_the_detail(self):
        """
        The list response sometimes omits the level, and the detail carries it.

        The fixture's last row has severity 0 on the row and 3 on the detail, so a row-only read would
        grade it Info instead of Medium.
        """
        finding = self.by_uid("halosecurity_many_vuln.json")["9005:0"]
        self.assertEqual("Medium", finding.severity)

    def test_the_detail_is_merged_from_a_separate_lookup(self):
        """
        Halo splits an issue across two calls: the list row, and a per-issue detail.

        The description, category, CVEs and PCI flag exist ONLY on the detail, so a row-only import
        would produce findings with no prose at all. The export carries the details keyed by issue id.
        """
        raw = json.loads((get_unit_tests_scans_path("halosecurity")
                          / "halosecurity_one_vuln.json").read_text(encoding="utf-8"))
        row = raw["list"][0]
        self.assertNotIn("description", row["issue"])
        self.assertIn("9001", raw["details"])
        self.assertIn("description", raw["details"]["9001"])

        finding = self.parse("halosecurity_one_vuln.json")[0]
        self.assertIn("The certificate presented by the host expires shortly.", finding.description)

    def test_a_row_with_no_detail_still_imports(self):
        """Issue 9003 has no entry in the details map."""
        finding = self.by_uid("halosecurity_many_vuln.json")["9003:3002"]
        self.assertEqual("Acknowledged false positive", finding.title)
        self.assertNotIn("**Category:**", finding.description)
        self.assertIn("**Target:** shop.example.com", finding.description)

    def test_a_detail_nested_on_the_row_is_also_accepted(self):
        report = io.StringIO(json.dumps({"list": [{
            "issue": {"issue_id": 1, "name": "An issue", "severity": 4},
            "target": {"target_id": 2, "target": "app.example.com"},
            "status": {"target_id": 2, "status": "new"},
            "detail": {"issue_id": 1, "description": "Nested detail.", "category": "Headers"},
        }]}))
        finding = list(HaloSecurityParser().get_findings(report, Test()))[0]
        self.assertIn("Nested detail.", finding.description)
        self.assertIn("**Category:** Headers", finding.description)

    def test_a_details_array_is_indexed_by_issue_id(self):
        report = io.StringIO(json.dumps({
            "list": [{
                "issue": {"issue_id": 1, "name": "An issue", "severity": 4},
                "target": {"target_id": 2, "target": "app.example.com"},
                "status": {"target_id": 2, "status": "new"},
            }],
            "details": [{"issue_id": 1, "description": "From an array.", "category": "Headers"}],
        }))
        finding = list(HaloSecurityParser().get_findings(report, Test()))[0]
        self.assertIn("From an array.", finding.description)

    def test_the_same_issue_on_two_hosts_is_two_findings(self):
        """
        Halo reports an issue once per affected host, and the target is part of the identity.

        Keying on the issue id alone would collapse them into one finding and lose a host.
        """
        findings = self.by_uid("halosecurity_many_vuln.json")
        self.assertIn("9002:3001", findings)
        self.assertIn("9002:3002", findings)
        self.assertEqual(
            {"Missing HSTS header"},
            {findings["9002:3001"].title, findings["9002:3002"].title},
        )
        # And their states differ, which is the point of keeping them separate.
        self.assertTrue(findings["9002:3001"].active)
        self.assertFalse(findings["9002:3002"].active)

    def test_the_status_decides_the_defectdojo_state(self):
        findings = self.by_uid("halosecurity_many_vuln.json")

        fixed = findings["9002:3002"]
        self.assertFalse(fixed.active)
        self.assertTrue(fixed.is_mitigated)

        false_positive = findings["9003:3002"]
        self.assertFalse(false_positive.active)
        self.assertTrue(false_positive.false_p)

        risk_accepted = findings["9004:3003"]
        self.assertFalse(risk_accepted.active)
        self.assertTrue(risk_accepted.risk_accepted)

        new = findings["9002:3001"]
        self.assertTrue(new.active)

    def test_only_confirmed_fixing_and_fixed_count_as_verified(self):
        """
        A new or investigating issue has not been confirmed by anyone yet.

        Marking those verified would overstate what Halo knows.
        """
        findings = self.by_uid("halosecurity_many_vuln.json")
        self.assertTrue(findings["9001:3001"].verified)    # confirmed
        self.assertTrue(findings["9002:3002"].verified)    # fixed
        self.assertFalse(findings["9002:3001"].verified)   # new
        self.assertFalse(findings["9003:3002"].verified)   # ack_false_positive

    def test_the_unassigned_placeholder_is_not_reported(self):
        """Halo writes "Nobody" to mean unassigned, so reporting it would be noise."""
        finding = self.by_uid("halosecurity_many_vuln.json")["9002:3001"]
        self.assertNotIn("**Assigned to:**", finding.description)
        self.assertNotIn("Nobody", finding.description)

    def test_the_pci_flag_becomes_a_line_and_a_tag(self):
        finding = self.parse("halosecurity_one_vuln.json")[0]
        self.assertIn("**PCI:** this issue affects PCI compliance", finding.description)
        self.assertIn("pci", finding.unsaved_tags)

    def test_a_non_pci_issue_has_neither(self):
        finding = self.by_uid("halosecurity_many_vuln.json")["9002:3001"]
        self.assertNotIn("**PCI:**", finding.description)
        self.assertNotIn("pci", finding.unsaved_tags)

    def test_tags_are_the_category_pci_flag_and_status(self):
        finding = self.parse("halosecurity_one_vuln.json")[0]
        self.assertEqual(["Encryption", "pci", "confirmed"], finding.unsaved_tags)

    def test_cves_come_from_the_detail_and_are_deduplicated(self):
        """The fixture repeats one identifier to prove the deduplication."""
        finding = self.by_uid("halosecurity_many_vuln.json")["9004:3003"]
        self.assertEqual(["CVE-2000-0001", "CVE-2000-0002"], finding.unsaved_vulnerability_ids)

    def test_an_issue_with_no_cves_has_none(self):
        finding = self.parse("halosecurity_one_vuln.json")[0]
        self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_the_scanned_host_is_recorded(self):
        """
        This scan type's deduplication hashes the ENDPOINTS.

        An unpopulated endpoint would leave the hash computed over nothing and every rescan would
        reimport. Asserted through get_unsaved_locations so it passes in both
        V3_FEATURE_LOCATIONS modes.
        """
        finding = self.parse("halosecurity_one_vuln.json")[0]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("app.example.com", locations[0].host)

    def test_endpoints_is_in_the_dedupe_fields_so_it_must_be_populated(self):
        self.assertIn("endpoints", HaloSecurityParser().get_dedupe_fields())

    def test_a_row_with_no_target_records_no_location(self):
        finding = self.by_uid("halosecurity_many_vuln.json")["9005:0"]
        self.assertEqual([], self.get_unsaved_locations(finding))

    def test_a_row_with_no_name_anywhere_is_named_from_its_identity(self):
        report = io.StringIO(json.dumps({"list": [{
            "issue": {"issue_id": 7, "name": "", "severity": 2},
            "status": {"target_id": 8, "status": "new"},
        }]}))
        finding = list(HaloSecurityParser().get_findings(report, Test()))[0]
        self.assertEqual("Halo Security issue 7:8", finding.title)

    def test_a_row_with_no_issue_block_is_skipped(self):
        report = io.StringIO(json.dumps({"list": [
            {"target": {"target_id": 1, "target": "app.example.com"}},
            {"issue": {"issue_id": 1, "name": "An issue", "severity": 3}},
        ]}))
        findings = list(HaloSecurityParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("An issue", findings[0].title)

    def test_the_finding_is_dated_today(self):
        """
        Halo's list response carries no discovery date, so the connector stamps today.

        Asserted as a range so it cannot flake on a date rollover.
        """
        finding = self.parse("halosecurity_one_vuln.json")[0]
        self.assertLessEqual(abs((finding.date - datetime.now(tz=UTC).date()).days), 1)

    def test_a_bare_array_of_rows_is_accepted(self):
        report = io.StringIO(json.dumps([{
            "issue": {"issue_id": 1, "name": "An issue", "severity": 4},
            "status": {"target_id": 2, "status": "new"},
        }]))
        self.assertEqual(1, len(list(HaloSecurityParser().get_findings(report, Test()))))

    def test_a_repeated_issue_and_target_pair_collapses(self):
        row = {"issue": {"issue_id": 1, "name": "An issue", "severity": 3},
               "status": {"target_id": 2, "status": "new"}}
        report = io.StringIO(json.dumps({"list": [row, row]}))
        self.assertEqual(1, len(list(HaloSecurityParser().get_findings(report, Test()))))

    def test_an_unexpected_shape_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(HaloSecurityParser().get_findings(io.StringIO('"nope"'), Test()))
        self.assertIn("list", str(raised.exception))
