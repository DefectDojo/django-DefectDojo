import io
import json
from datetime import date

from dojo.models import Finding, Test
from dojo.tools.yeswehack.parser import YesWeHackParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestYesWeHackParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("yeswehack") / filename).open(encoding="utf-8") as file:
            return list(YesWeHackParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(YesWeHackParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def by_uid(self, filename):
        return {f.unique_id_from_tool: f for f in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal ScanTypeName in the YesWeHack connector verbatim.

        Any drift and a customer who uploads an export and also syncs the API gets two
        un-deduplicated copies of every finding.
        """
        parser = YesWeHackParser()
        self.assertEqual(["YesWeHack - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "YesWeHack - Connectors Import",
            parser.get_label_for_scan_types("YesWeHack - Connectors Import"),
        )

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("yeswehack_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("yeswehack_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring ToFinding in the connector's converter."""
        findings = self.parse("yeswehack_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("SQL injection on the search endpoint", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("40001", finding.unique_id_from_tool)
        # vuln_id_from_tool is the human-facing local id, not the numeric one.
        self.assertEqual("GENERIC-2026-0001", finding.vuln_id_from_tool)
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", finding.cvssv3)
        self.assertEqual(date(2026, 7, 20), finding.date)
        self.assertEqual(["yeswehack"], finding.unsaved_tags)
        self.assertFalse(finding.static_finding)
        self.assertTrue(finding.dynamic_finding)

    def test_the_description_uses_the_shared_formatters_markdown(self):
        """
        The connector builds this with the shared formatter: "* **Prefix** text" bullets and
        "### Heading" sections.

        Getting the shape wrong would not break the import but would make every finding read
        differently from the connector's, which is the thing this parser exists to match.
        """
        finding = self.parse("yeswehack_one_vuln.json")[0]
        self.assertIn("* **Report:** GENERIC-2026-0001\n", finding.description)
        self.assertIn("* **Bug type:** SQL Injection\n", finding.description)
        self.assertIn("* **Category:** Injection\n", finding.description)
        self.assertIn("* **Scope:** app.example.com\n", finding.description)
        self.assertIn("* **Endpoint:** https://app.example.com/search\n", finding.description)
        self.assertIn("### Description\n\n", finding.description)
        self.assertIn("### Impact\n\n", finding.description)
        self.assertIn("An attacker can read the whole database.", finding.description)

    def test_severity_falls_through_criticity_then_priority_name_then_slug(self):
        """
        The connector tries three sources in order.

        Falling straight to Info when the CVSS criticity is unset would throw away the priority
        YesWeHack did set - the fixture's second report has exactly that shape.
        """
        findings = self.by_uid("yeswehack_many_vuln.json")
        # No criticity, priority name "Medium" recognised.
        self.assertEqual("Medium", findings["40002"].severity)
        # Criticity is an unrecognised word AND the priority name is too, so the slug decides.
        self.assertEqual("Low", findings["40003"].severity)

    def test_the_severity_resolution_directly(self):
        parser = YesWeHackParser()
        self.assertEqual("Critical", parser.severity({}, {"criticity": "critical"}))
        self.assertEqual("High", parser.severity({"priority": {"name": "High"}}, {}))
        self.assertEqual("Low", parser.severity({"priority": {"name": "?", "slug": "low"}}, {}))
        # YesWeHack's own Info spellings.
        for word in ("info", "informative", "none"):
            self.assertEqual("Info", parser.severity({}, {"criticity": word}), word)
        self.assertEqual("Info", parser.severity({}, {}))

    def test_the_workflow_state_becomes_the_defectdojo_state(self):
        """
        YesWeHack's state carries real triage information, and the connector translates each one.

        Importing everything as active would put resolved, rejected and duplicate reports back in
        front of the team.
        """
        findings = self.by_uid("yeswehack_many_vuln.json")

        accepted = findings["40001"]
        self.assertTrue(accepted.active)
        self.assertTrue(accepted.verified)

        resolved = findings["40002"]
        self.assertFalse(resolved.active)
        self.assertTrue(resolved.is_mitigated)

        wont_fix = findings["40003"]
        self.assertFalse(wont_fix.active)
        self.assertTrue(wont_fix.risk_accepted)

        rejected = findings["40004"]
        self.assertFalse(rejected.active)
        self.assertTrue(rejected.false_p)

        duplicate = findings["40005"]
        self.assertFalse(duplicate.active)
        self.assertTrue(duplicate.duplicate)

        out_of_scope = findings["40006"]
        self.assertFalse(out_of_scope.active)
        self.assertFalse(out_of_scope.is_mitigated)
        self.assertFalse(out_of_scope.false_p)

    def test_an_unrecognised_state_stays_active(self):
        """
        The safe side of the assumption: a state YesWeHack adds later must not silently close a
        finding.
        """
        finding = self.by_uid("yeswehack_many_vuln.json")["40007"]
        self.assertTrue(finding.active)
        self.assertFalse(finding.is_mitigated)
        self.assertFalse(finding.false_p)
        self.assertFalse(finding.duplicate)
        self.assertFalse(finding.risk_accepted)

    def test_the_status_mapping_directly(self):
        parser = YesWeHackParser()
        for state, checks in (
            ("new", {"active": True}),
            ("under_review", {"active": True}),
            ("accepted", {"active": True, "verified": True}),
            ("resolved", {"active": False, "is_mitigated": True}),
            ("auto_close", {"active": False, "is_mitigated": True}),
            ("wont_fix", {"active": False, "risk_accepted": True}),
            ("invalid", {"active": False, "false_p": True}),
            ("informative", {"active": False}),
        ):
            finding = Finding()
            parser.apply_status(finding, state)
            for attribute, expected in checks.items():
                self.assertEqual(expected, getattr(finding, attribute), f"{state}.{attribute}")

    def test_a_report_with_no_title_falls_back_to_the_local_id_then_the_numeric_id(self):
        findings = self.by_uid("yeswehack_many_vuln.json")
        self.assertEqual("YesWeHack report 40003", findings["40003"].title)
        # And with no local id either, vuln_id_from_tool is the numeric id.
        self.assertEqual("40003", findings["40003"].vuln_id_from_tool)

    def test_cves_are_extracted_from_the_prose_fields(self):
        """
        YesWeHack has no CVE field; the connector scans title, description, impact and technical
        information.

        The fixture puts the identifier only in the technical information, which is the field easiest
        to forget.
        """
        finding = self.parse("yeswehack_one_vuln.json")[0]
        self.assertEqual(["CVE-2000-0002"], finding.unsaved_vulnerability_ids)

    def test_a_report_with_no_cve_has_none(self):
        finding = self.by_uid("yeswehack_many_vuln.json")["40002"]
        self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_the_endpoint_prefers_the_reported_endpoint_over_the_scope(self):
        """Asserted through get_unsaved_locations so it passes in both V3_FEATURE_LOCATIONS modes."""
        finding = self.parse("yeswehack_one_vuln.json")[0]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("app.example.com", locations[0].host)

    def test_the_endpoint_falls_back_to_the_scope(self):
        finding = self.by_uid("yeswehack_many_vuln.json")["40002"]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("app.example.com", locations[0].host)

    def test_a_report_with_neither_endpoint_nor_scope_records_none(self):
        finding = self.by_uid("yeswehack_many_vuln.json")["40003"]
        self.assertEqual([], self.get_unsaved_locations(finding))

    def test_the_alternative_timestamp_layouts_are_accepted(self):
        """
        The connector tries several layouts, so a non-RFC3339 stamp still dates the finding.

        Supporting only RFC3339 would leave those findings undated.
        """
        findings = self.by_uid("yeswehack_many_vuln.json")
        self.assertEqual(date(2026, 7, 21), findings["40002"].date)   # "2026-07-21 10:00:00"
        self.assertEqual(date(2026, 7, 22), findings["40003"].date)   # "2026-07-22"
        self.assertIsNone(findings["40004"].date)                     # unparseable

    def test_a_zero_score_is_left_unset(self):
        finding = self.by_uid("yeswehack_many_vuln.json")["40002"]
        self.assertIsNone(finding.cvssv3_score)

    def test_a_bare_array_is_accepted(self):
        report = io.StringIO(json.dumps([{
            "id": 1, "title": "A report", "cvss": {"criticity": "low"},
            "status": {"workflow_state": "new"},
        }]))
        findings = list(YesWeHackParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("Low", findings[0].severity)

    def test_a_repeated_report_id_collapses(self):
        row = {"id": 1, "title": "A report", "cvss": {"criticity": "low"},
               "status": {"workflow_state": "new"}}
        report = io.StringIO(json.dumps({"items": [row, row]}))
        self.assertEqual(1, len(list(YesWeHackParser().get_findings(report, Test()))))

    def test_an_unexpected_shape_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(YesWeHackParser().get_findings(io.StringIO('"nope"'), Test()))
        self.assertIn("items", str(raised.exception))

    def test_an_endpoint_with_a_port_is_split_rather_than_kept_whole(self):
        """
        A researcher writes whatever the programme scope allows, so the value may be a full URL.

        Keeping "host:port" in the host field fails DefectDojo's validation, and that fails the whole
        import rather than the one finding.
        """
        findings = self.parse_string({"items": [{
            "id": 1, "title": "A report", "severity": "high", "status": "accepted",
            "end_point": "https://app.example.com:8443/login",
        }]})
        location = self.get_unsaved_locations(findings[0])[0]
        self.assertEqual("app.example.com", location.host)
        self.assertEqual(8443, location.port)
        self.assertEqual("https", location.protocol)

    def test_an_endpoint_that_cannot_be_a_host_is_dropped(self):
        findings = self.parse_string({"items": [{
            "id": 1, "title": "A report", "severity": "high", "status": "accepted",
            "end_point": "the mobile app",
        }]})
        self.assertEqual([], self.get_unsaved_locations(findings[0]))
