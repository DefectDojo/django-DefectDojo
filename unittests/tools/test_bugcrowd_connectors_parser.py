import io
import json

from dojo.models import Finding, Test
from dojo.tools.bugcrowd.parser import BugCrowdParser
from dojo.tools.bugcrowd_connectors.parser import BugcrowdConnectorsParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestBugcrowdConnectorsParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("bugcrowd_connectors") / filename
        with path.open(encoding="utf-8") as file:
            return list(BugcrowdConnectorsParser().get_findings(file, Test()))

    def by_uid(self, filename):
        return {f.unique_id_from_tool: f for f in self.parse(filename)}

    def test_scan_type_matches_the_connector_and_does_not_clash_with_the_csv_parser(self):
        """
        Must equal ScanTypeName in the Bugcrowd connector verbatim.

        DefectDojo already ships a Bugcrowd CSV parser under "BugCrowd Scan" - note the capital C.
        These are two different formats and must claim two different scan types, or one would shadow
        the other in the import dropdown.
        """
        parser = BugcrowdConnectorsParser()
        self.assertEqual(["Bugcrowd - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "Bugcrowd - Connectors Import",
            parser.get_label_for_scan_types("Bugcrowd - Connectors Import"),
        )
        # The shipped CSV parser keeps its own scan type, untouched.
        self.assertEqual(["BugCrowd Scan"], BugCrowdParser().get_scan_types())
        self.assertNotEqual(BugCrowdParser().get_scan_types(), parser.get_scan_types())

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("bugcrowd_connectors_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("bugcrowd_connectors_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring toFinding in the connector's converter."""
        findings = self.parse("bugcrowd_connectors_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Critical", finding.severity)   # P1
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("00000000-0000-4000-8000-000000000001", finding.unique_id_from_tool)
        self.assertEqual("2026-07-28", finding.date)
        self.assertEqual("Encode the display name before rendering it.", finding.mitigation)
        self.assertEqual(
            "Submitting a crafted display name stores script that runs for other users.",
            finding.steps_to_reproduce,
        )
        self.assertFalse(finding.static_finding)
        self.assertTrue(finding.dynamic_finding)

    def test_the_priority_ladder_is_the_connectors(self):
        """Bugcrowd grades P1 to P5; only P1-P4 map, and P5 falls through to Info."""
        findings = self.by_uid("bugcrowd_connectors_many_vuln.json")
        self.assertEqual("Critical", findings["00000000-0000-4000-8000-000000000001"].severity)  # P1
        self.assertEqual("High", findings["00000000-0000-4000-8000-000000000009"].severity)      # P2
        self.assertEqual("Medium", findings["00000000-0000-4000-8000-000000000002"].severity)    # P3
        self.assertEqual("Low", findings["00000000-0000-4000-8000-000000000004"].severity)       # P4
        self.assertEqual("Info", findings["00000000-0000-4000-8000-000000000008"].severity)      # P5

    def test_a_submission_still_being_triaged_is_not_imported(self):
        """
        "triaging" is deliberately absent from the importable states.

        A submission mid-triage has no confirmed verdict, so the connector waits rather than
        importing a maybe. Importing it would put unvetted researcher claims in the queue.
        """
        uids = set(self.by_uid("bugcrowd_connectors_many_vuln.json"))
        self.assertNotIn("00000000-0000-4000-8000-000000000006", uids)
        self.assertEqual(8, len(uids))

    def test_the_state_becomes_the_defectdojo_state(self):
        findings = self.by_uid("bugcrowd_connectors_many_vuln.json")

        triaged = findings["00000000-0000-4000-8000-000000000001"]
        self.assertTrue(triaged.active)
        self.assertTrue(triaged.verified)

        resolved = findings["00000000-0000-4000-8000-000000000002"]
        self.assertFalse(resolved.active)
        self.assertTrue(resolved.is_mitigated)

        not_reproducible = findings["00000000-0000-4000-8000-000000000003"]
        self.assertFalse(not_reproducible.active)
        self.assertTrue(not_reproducible.false_p)

        out_of_scope = findings["00000000-0000-4000-8000-000000000004"]
        self.assertFalse(out_of_scope.active)
        self.assertTrue(out_of_scope.out_of_scope)

        unresolved = findings["00000000-0000-4000-8000-000000000009"]
        self.assertTrue(unresolved.active)

    def test_a_hyphenated_state_is_normalised(self):
        """
        The fixture spells this one "out-of-scope" while Bugcrowd elsewhere uses underscores.

        Without normalisation it would not match the importable set and would be dropped silently.
        """
        finding = self.by_uid("bugcrowd_connectors_many_vuln.json")["00000000-0000-4000-8000-000000000004"]
        self.assertTrue(finding.out_of_scope)

    def test_a_not_applicable_submission_is_closed_and_regraded_to_info(self):
        """
        The connector overrides the priority for this state.

        A P1 Bugcrowd then judged not applicable must not sit in the queue as Critical.
        """
        finding = self.by_uid("bugcrowd_connectors_many_vuln.json")["00000000-0000-4000-8000-000000000005"]
        self.assertFalse(finding.active)
        self.assertEqual("Info", finding.severity)

    def test_an_informational_submission_is_imported_but_not_active(self):
        """A courtesy report is worth recording without sitting in the open queue."""
        finding = self.by_uid("bugcrowd_connectors_many_vuln.json")["00000000-0000-4000-8000-000000000008"]
        self.assertFalse(finding.active)
        self.assertFalse(finding.is_mitigated)
        self.assertFalse(finding.false_p)

    def test_a_new_submission_is_active_but_not_verified(self):
        finding = self.by_uid("bugcrowd_connectors_many_vuln.json")["00000000-0000-4000-8000-000000000007"]
        self.assertTrue(finding.active)
        self.assertFalse(finding.verified)

    def test_the_state_helpers_directly(self):
        parser = BugcrowdConnectorsParser()
        self.assertTrue(parser.is_active("unresolved"))
        self.assertTrue(parser.is_active("triaged"))
        self.assertTrue(parser.is_active("new"))
        for state in ("resolved", "not_reproducible", "out_of_scope", "informational"):
            self.assertFalse(parser.is_active(state), state)
        self.assertTrue(parser.is_verified("triaged"))
        self.assertFalse(parser.is_verified("new"))
        self.assertFalse(parser.is_verified("triaging"))
        self.assertTrue(parser.is_verified("resolved"))
        self.assertEqual("out_of_scope", parser.normalise_state(" Out-Of-Scope "))

    def test_awkward_title_characters_are_replaced(self):
        """
        The connector rewrites colons, quotes and at-signs, but only when the title needs it.

        The fixture's title has both a colon and an "@", so it exercises the replacement path.
        """
        finding = self.parse("bugcrowd_connectors_one_vuln.json")[0]
        self.assertEqual(
            "Stored XSS in the profile page reachable via atmention", finding.title,
        )
        self.assertNotIn(":", finding.title)
        self.assertNotIn("@", finding.title)

    def test_a_clean_title_is_left_alone(self):
        parser = BugcrowdConnectorsParser()
        self.assertEqual("Resolved rate limit issue", parser.title("Resolved rate limit issue"))
        self.assertEqual("A-title, with 1 + 2 chars.", parser.title("A-title, with 1 + 2 chars."))

    def test_a_very_long_title_is_shortened_with_an_ellipsis(self):
        """
        DefectDojo's title column is 511 characters, so an over-long title has to be cut.

        The connector collapses whitespace first, which is why the assertion checks the collapsed
        length rather than the original.
        """
        parser = BugcrowdConnectorsParser()
        long_title = "word " * 200
        shortened = parser.title(long_title)
        self.assertEqual(511, len(shortened))
        self.assertTrue(shortened.endswith("..."))
        # Whitespace runs collapse to single spaces.
        self.assertNotIn("  ", parser.title("a    b"))

    def test_the_description_uses_the_connectors_fixed_layout(self):
        finding = self.parse("bugcrowd_connectors_one_vuln.json")[0]
        self.assertIn("Bugcrowd details:", finding.description)
        self.assertIn("- Severity: P1", finding.description)
        self.assertIn(
            "- Bug Url: [https://app.example.com/profile/edit](https://app.example.com/profile/edit)",
            finding.description,
        )
        self.assertIn("Bugcrowd link: [https://tracker.bugcrowd.com/generic-app", finding.description)

    def test_the_tracker_link_uses_the_programme_code_from_the_export(self):
        """
        The connector reads the programme code from the product's configuration, not the payload.

        An export only carries it if whoever produced it added it, so it is read from the envelope
        when present and the link is still built without it otherwise.
        """
        finding = self.parse("bugcrowd_connectors_one_vuln.json")[0]
        self.assertEqual(
            "https://tracker.bugcrowd.com/generic-app"
            "/submissions/00000000-0000-4000-8000-000000000001",
            finding.references,
        )

        report = io.StringIO(json.dumps({"data": [{
            "id": "s1", "attributes": {"title": "A submission", "severity": 3, "state": "triaged"},
            "links": {"self": "/submissions/s1"},
        }]}))
        without = list(BugcrowdConnectorsParser().get_findings(report, Test()))[0]
        # The connector concatenates base + code + self link, so an empty code leaves a double
        # slash. Reproduced rather than tidied: the connector never has an empty code (it comes from
        # a required product attribute), so "fixing" it here would be the only difference between the
        # two paths for an export that does carry one.
        self.assertEqual("https://tracker.bugcrowd.com//submissions/s1", without.references)

    def test_the_reported_url_is_recorded(self):
        """Asserted through get_unsaved_locations so it passes in both V3_FEATURE_LOCATIONS modes."""
        finding = self.parse("bugcrowd_connectors_one_vuln.json")[0]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("app.example.com", locations[0].host)
        self.assertEqual("https", locations[0].protocol)

    def test_a_bare_host_bug_url_is_still_recorded_as_a_host(self):
        """
        The connector prefixes a schemeless value with "//".

        Without that, DefectDojo's URI parser reads the whole thing as a path and the host is lost.
        """
        finding = self.by_uid("bugcrowd_connectors_many_vuln.json")["00000000-0000-4000-8000-000000000002"]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("app.example.com", locations[0].host)

    def test_an_explicit_port_is_carried_through(self):
        finding = self.by_uid("bugcrowd_connectors_many_vuln.json")["00000000-0000-4000-8000-000000000009"]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual(8443, locations[0].port)

    def test_a_submission_with_no_bug_url_records_no_location(self):
        finding = self.by_uid("bugcrowd_connectors_many_vuln.json")["00000000-0000-4000-8000-000000000003"]
        self.assertEqual([], self.get_unsaved_locations(finding))

    def test_an_already_flattened_export_is_accepted(self):
        report = io.StringIO(json.dumps([{
            "id": "s1", "title": "A flattened submission", "severity": 2, "state": "triaged",
            "submitted_at": "2026-07-01T00:00:00Z", "description": "Details.",
            "remediation_advice": "Fix it.", "bug_url": "https://app.example.com/",
            "self_link": "/submissions/s1",
        }]))
        finding = list(BugcrowdConnectorsParser().get_findings(report, Test()))[0]
        self.assertEqual("A flattened submission", finding.title)
        self.assertEqual("High", finding.severity)
        self.assertEqual("2026-07-01", finding.date)

    def test_a_repeated_submission_id_collapses(self):
        row = {"id": "same", "attributes": {"title": "A submission", "severity": 3, "state": "triaged"}}
        report = io.StringIO(json.dumps({"data": [row, row]}))
        self.assertEqual(1, len(list(BugcrowdConnectorsParser().get_findings(report, Test()))))

    def test_an_unexpected_shape_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(BugcrowdConnectorsParser().get_findings(io.StringIO('"nope"'), Test()))
        self.assertIn("data", str(raised.exception))
