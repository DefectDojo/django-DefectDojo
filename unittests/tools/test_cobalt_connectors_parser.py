import io
import json
from datetime import date

from dojo.models import Finding, Test
from dojo.tools.cobalt.parser import CobaltParser
from dojo.tools.cobalt_connectors.parser import CobaltConnectorsParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestCobaltConnectorsParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("cobalt_connectors") / filename
        with path.open(encoding="utf-8") as file:
            return list(CobaltConnectorsParser().get_findings(file, Test()))

    def by_uid(self, filename):
        return {f.unique_id_from_tool: f for f in self.parse(filename)}

    def test_scan_type_matches_the_connector_and_does_not_clash_with_the_csv_parser(self):
        """
        Must equal ScanTypeName in the Cobalt connector verbatim.

        DefectDojo already ships a Cobalt CSV parser under "Cobalt.io Scan". Two formats, two scan
        types - if they collided one would shadow the other in the import dropdown.
        """
        parser = CobaltConnectorsParser()
        self.assertEqual(["Cobalt.io - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "Cobalt.io - Connectors Import",
            parser.get_label_for_scan_types("Cobalt.io - Connectors Import"),
        )
        self.assertEqual(["Cobalt.io Scan"], CobaltParser().get_scan_types())
        self.assertNotEqual(CobaltParser().get_scan_types(), parser.get_scan_types())

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("cobalt_connectors_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("cobalt_connectors_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring toFinding in the connector's converter."""
        findings = self.parse("cobalt_connectors_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual(
            "Authenticated SQL injection in the reporting export", finding.title,
        )
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("fnd_0000000001", finding.unique_id_from_tool)
        self.assertEqual("fnd_0000000001", finding.vuln_id_from_tool)
        self.assertEqual(89, finding.cwe)
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual(
            "Use parameterised queries for the date range.", finding.mitigation,
        )
        self.assertIn("Log in as a standard user", finding.steps_to_reproduce)
        self.assertEqual(
            "Direct database access with an authenticated low-privilege account.",
            finding.severity_justification,
        )
        self.assertEqual("https://app.example.com/findings/fnd_0000000001", finding.url)
        self.assertFalse(finding.static_finding)
        self.assertTrue(finding.dynamic_finding)

    def test_the_finding_is_unwrapped_from_the_resource_and_the_link_from_outside_it(self):
        """
        Cobalt nests the finding under "resource" but puts the deep link OUTSIDE it, at
        links.ui.url.

        Reading the entry directly would find no fields at all; reading only the resource would lose
        the link, which is the only way back to the pentest report.
        """
        raw = json.loads((get_unit_tests_scans_path("cobalt_connectors")
                          / "cobalt_connectors_one_vuln.json").read_text(encoding="utf-8"))
        entry = raw["data"][0]
        self.assertIn("resource", entry)
        self.assertNotIn("title", entry)
        self.assertNotIn("ui", entry["resource"])

        finding = self.parse("cobalt_connectors_one_vuln.json")[0]
        self.assertEqual("fnd_0000000001", finding.unique_id_from_tool)
        self.assertEqual("https://app.example.com/findings/fnd_0000000001", finding.url)

    def test_the_created_date_comes_from_the_log_not_created_at(self):
        """
        Cobalt can carry a finding over from an earlier pentest, and then created_at is the
        carry-over date rather than when it was actually found.

        The fixture's carried-over finding was created in January but carried over in July; taking
        created_at would date it six months late.
        """
        findings = self.by_uid("cobalt_connectors_many_vuln.json")
        carried = findings["fnd_0000000008"]
        self.assertEqual(date(2026, 1, 5), carried.date)

        # And the one_vuln finding's log "created" entry precedes its created_at too.
        first = findings["fnd_0000000001"]
        self.assertEqual(date(2026, 7, 15), first.date)

    def test_the_date_falls_back_to_created_at_with_no_log(self):
        finding = self.by_uid("cobalt_connectors_many_vuln.json")["fnd_0000000003"]
        self.assertEqual(date(2026, 7, 11), finding.date)

    def test_the_last_status_update_is_the_latest_log_timestamp(self):
        finding = self.by_uid("cobalt_connectors_many_vuln.json")["fnd_0000000001"]
        self.assertEqual(date(2026, 7, 18), finding.last_status_update)

    def test_a_finding_with_no_log_has_no_last_status_update(self):
        finding = self.by_uid("cobalt_connectors_many_vuln.json")["fnd_0000000003"]
        self.assertIsNone(finding.last_status_update)

    def test_the_pentest_state_becomes_the_defectdojo_state(self):
        findings = self.by_uid("cobalt_connectors_many_vuln.json")

        need_fix = findings["fnd_0000000001"]
        self.assertTrue(need_fix.active)
        self.assertTrue(need_fix.verified)

        valid_fix = findings["fnd_0000000002"]
        self.assertFalse(valid_fix.active)
        self.assertTrue(valid_fix.is_mitigated)

        invalid = findings["fnd_0000000003"]
        self.assertFalse(invalid.active)
        self.assertTrue(invalid.false_p)

        out_of_scope = findings["fnd_0000000006"]
        self.assertFalse(out_of_scope.active)
        self.assertTrue(out_of_scope.out_of_scope)

    def test_a_duplicate_and_an_accepted_risk_stay_active(self):
        """
        The connector flags these without closing them.

        Only fixed, invalid and out-of-scope close a finding, so a duplicate or an accepted risk is
        still visible - which is deliberate, since both may still need tracking.
        """
        findings = self.by_uid("cobalt_connectors_many_vuln.json")

        duplicate = findings["fnd_0000000004"]
        self.assertTrue(duplicate.active)
        self.assertTrue(duplicate.duplicate)

        risk_accepted = findings["fnd_0000000005"]
        self.assertTrue(risk_accepted.active)
        self.assertTrue(risk_accepted.risk_accepted)

    def test_new_and_triaging_are_the_only_unverified_states(self):
        """Cobalt only moves a finding past those once the pentest team has verified it."""
        findings = self.by_uid("cobalt_connectors_many_vuln.json")
        self.assertFalse(findings["fnd_0000000007"].verified)   # new
        for uid in ("fnd_0000000001", "fnd_0000000002", "fnd_0000000004", "fnd_0000000008"):
            self.assertTrue(findings[uid].verified, uid)

    def test_a_state_cobalt_adds_later_is_not_imported(self):
        """
        Every documented state is importable, so an unknown one means the API changed.

        Skipping it is safer than guessing which DefectDojo state it maps to.
        """
        uids = set(self.by_uid("cobalt_connectors_many_vuln.json"))
        self.assertNotIn("fnd_0000000009", uids)
        self.assertEqual(8, len(uids))

    def test_the_cvss_v3_entry_is_chosen_from_several_versions(self):
        """
        Cobalt can report v2 and v3 side by side, and cvssv3 is a v3 field.

        The fixture lists the v2 entry FIRST, so taking whichever came first would put a v2 vector in
        a v3 column.
        """
        finding = self.parse("cobalt_connectors_one_vuln.json")[0]
        self.assertEqual(
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", finding.cvssv3,
        )
        self.assertEqual(8.8, finding.cvssv3_score)

    def test_the_cvss_selection_directly(self):
        parser = CobaltConnectorsParser()
        self.assertEqual(("v3", 9.0), parser.cvss_v3([
            {"version": "2.0", "vector": "v2", "score": 7.0},
            {"version": "3.0", "vector": "v3", "score": 9.0},
        ]))
        # A v2-only report yields nothing, because it cannot go in a v3 field.
        self.assertEqual(("", 0), parser.cvss_v3([{"version": "2.0", "vector": "v2", "score": 7.0}]))
        self.assertEqual(("", 0), parser.cvss_v3(None))

    def test_impact_and_likelihood_are_reported_even_when_zero(self):
        """
        Cobalt scores these numerically, and zero is a real score rather than a missing value.

        A plain truthiness check would drop the zero and silently omit the line.
        """
        finding = self.by_uid("cobalt_connectors_many_vuln.json")["fnd_0000000003"]
        self.assertIn("- Impact: 0", finding.description)
        self.assertIn("- Likelihood: 0", finding.description)

    def test_the_description_carries_the_details_block_and_the_link(self):
        finding = self.parse("cobalt_connectors_one_vuln.json")[0]
        self.assertIn("The date range parameters are concatenated", finding.description)
        self.assertIn("Cobalt.io details:\n- Impact: 3\n- Likelihood: 3", finding.description)
        self.assertIn(
            "Cobalt.io link:\nhttps://app.example.com/findings/fnd_0000000001",
            finding.description,
        )

    def test_a_finding_with_no_link_omits_the_link_section(self):
        finding = self.by_uid("cobalt_connectors_many_vuln.json")["fnd_0000000005"]
        self.assertNotIn("Cobalt.io link:", finding.description)
        self.assertIsNone(finding.url)

    def test_a_long_title_is_cut_on_a_word_boundary(self):
        """
        The connector prefers a clean word boundary over using the full 511-character budget.

        Cutting mid-word would leave a fragment in the finding list.
        """
        parser = CobaltConnectorsParser()
        title = ("averylongword " * 60).strip()
        shortened = parser.shorten_title(title)
        self.assertTrue(shortened.endswith("..."))
        self.assertLessEqual(len(shortened), 511)
        # The character before the ellipsis is the end of a word, not a space.
        self.assertFalse(shortened[:-3].endswith(" "))
        self.assertTrue(shortened[:-3].endswith("averylongword"))

    def test_a_short_title_is_left_alone(self):
        parser = CobaltConnectorsParser()
        self.assertEqual("A short title", parser.shorten_title("  A short title  "))

    def test_the_affected_targets_are_recorded(self):
        """Asserted through get_unsaved_locations so it passes in both V3_FEATURE_LOCATIONS modes."""
        finding = self.parse("cobalt_connectors_one_vuln.json")[0]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("app.example.com", locations[0].host)

    def test_a_bare_host_target_is_recorded(self):
        finding = self.by_uid("cobalt_connectors_many_vuln.json")["fnd_0000000004"]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("app.example.com", locations[0].host)

    def test_a_finding_with_no_targets_records_none(self):
        finding = self.by_uid("cobalt_connectors_many_vuln.json")["fnd_0000000002"]
        self.assertEqual([], self.get_unsaved_locations(finding))

    def test_an_unrecognised_severity_is_info(self):
        finding = self.by_uid("cobalt_connectors_many_vuln.json")["fnd_0000000007"]
        self.assertEqual("Info", finding.severity)

    def test_an_unparseable_timestamp_leaves_the_date_unset(self):
        finding = self.by_uid("cobalt_connectors_many_vuln.json")["fnd_0000000007"]
        self.assertIsNone(finding.date)

    def test_an_already_flattened_export_is_accepted(self):
        report = io.StringIO(json.dumps([{
            "id": "f1", "title": "A flattened finding", "state": "need_fix", "severity": "High",
            "ui_url": "https://app.example.com/findings/f1", "created_at": "2026-07-01T00:00:00Z",
        }]))
        finding = list(CobaltConnectorsParser().get_findings(report, Test()))[0]
        self.assertEqual("A flattened finding", finding.title)
        self.assertEqual("High", finding.severity)
        self.assertEqual("https://app.example.com/findings/f1", finding.url)

    def test_a_repeated_finding_id_collapses(self):
        entry = {"resource": {"id": "same", "title": "A finding", "state": "need_fix",
                              "severity": "Low"}}
        report = io.StringIO(json.dumps({"data": [entry, entry]}))
        self.assertEqual(1, len(list(CobaltConnectorsParser().get_findings(report, Test()))))

    def test_an_unexpected_shape_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(CobaltConnectorsParser().get_findings(io.StringIO('"nope"'), Test()))
        self.assertIn("data", str(raised.exception))
