import io
import json
from datetime import UTC, datetime

from dojo.models import Finding, Test
from dojo.tools.intruder.parser import IntruderParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestIntruderParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("intruder") / filename).open(encoding="utf-8") as file:
            return list(IntruderParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(IntruderParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Intruder connector's ScanTypeName verbatim.

        Note it does NOT follow the "<Vendor> - Connectors Import" pattern the other connector scan
        types use, so it cannot be derived - it has to be copied.
        """
        parser = IntruderParser()
        self.assertEqual(["Intruder API Import"], parser.get_scan_types())
        self.assertEqual("Intruder API Import", parser.get_label_for_scan_types("Intruder API Import"))
        self.assertNotIn("Intruder - Connectors Import", parser.get_scan_types())

    def test_the_occurrence_id_is_part_of_the_hash_not_the_algorithm(self):
        """
        Intruder is the one connector scan type using the PLAIN hash_code algorithm.

        The occurrence id sits inside the hash fields instead of being paired with them, with title
        and severity guarding against id reuse. Copied from the connector's settings, not chosen.
        """
        self.assertEqual(
            ["unique_id_from_tool", "title", "severity"],
            IntruderParser().get_dedupe_fields(),
        )

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("intruder_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("intruder_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring ConvertOccurrence in the connector's finding_converter."""
        findings = self.parse("intruder_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("TLS certificate expires in under 14 days", finding.title)
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("500001", finding.unique_id_from_tool)
        self.assertEqual("9001", finding.vuln_id_from_tool)
        # The occurrence's own score wins over the issue's.
        self.assertEqual(8.1, finding.cvssv3_score)
        self.assertEqual(datetime(2024, 7, 1, tzinfo=UTC).date(), finding.date)
        self.assertEqual("Renew the certificate and redeploy it to every listener.", finding.mitigation)
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual(["intruder", "target:app.example.com"], finding.unsaved_tags)
        self.assertTrue(finding.active)
        self.assertFalse(finding.static_finding)
        self.assertTrue(finding.dynamic_finding)

        self.assertEqual(
            "* **Target:** app.example.com (production)\n"
            "* **Port:** 443\n"
            "* **Protocol:** tcp\n"
            "* **First seen:** 2024-07-01T12:00:00Z\n"
            "* **Exploit likelihood:** MEDIUM\n"
            "* **expires:** 2024-07-20\n"
            "* **issuer:** Example CA\n"
            "\n### Description\n\n"
            "The certificate presented by the service expires shortly.\n",
            finding.description,
        )

        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("app.example.com", locations[0].host)
        self.assertEqual(443, locations[0].port)

    def test_many_vuln(self):
        """One finding per occurrence: five occurrences across four issues."""
        self.assertEqual(5, len(self.parse("intruder_many_vuln.json")))

    def test_an_issue_with_no_occurrences_produces_nothing(self):
        """
        The occurrence is the finding: it is what says where the weakness actually is.

        An issue nothing is currently affected by is not imported.
        """
        titles = {finding.title for finding in self.parse("intruder_many_vuln.json")}
        self.assertNotIn("An issue with no occurrences", titles)

    def test_occurrences_may_be_nested_or_keyed_by_issue_id(self):
        """
        Intruder's own issue object carries "occurrences" as a URL string, not a list.

        That second call is what an export has to include, keyed by issue id - or nested as a list, as
        the one-issue sample does. Both have to work.
        """
        nested = self.parse("intruder_one_vuln.json")[0]
        keyed = self.by_uid("intruder_many_vuln.json")["500001"]
        self.assertEqual(nested.unique_id_from_tool, keyed.unique_id_from_tool)
        self.assertEqual(nested.title, keyed.title)

    def test_a_url_string_in_the_occurrences_field_is_not_mistaken_for_data(self):
        """The unexpanded API link must not be read as an occurrence list."""
        findings = self.parse_string({"results": [
            {"id": 1, "title": "An issue", "severity": "high",
             "occurrences": "https://api.example.com/v1/issues/1/occurrences"},
        ]})
        self.assertEqual(0, len(findings))

    def test_severity_labels(self):
        for label, expected in (("critical", "Critical"), ("high", "High"), ("medium", "Medium"),
                                ("low", "Low"), ("CRITICAL", "Critical"), ("not a label", "Info"),
                                ("", "Info")):
            with self.subTest(label=label):
                findings = self.parse_string({"results": [
                    {"id": 1, "title": "An issue", "severity": label,
                     "occurrences": [{"occurrence_id": 1, "target": "app.example.com"}]},
                ]})
                self.assertEqual(expected, findings[0].severity)

    def test_an_unrecognised_severity_is_info(self):
        finding = self.by_uid("intruder_many_vuln.json")["500005"]
        self.assertEqual("Info", finding.severity)

    def test_the_occurrence_score_wins_over_the_issue_score(self):
        """
        The same weakness scores differently per target - internet-facing is not the same risk as
        firewalled - so the occurrence's own score is preferred.
        """
        findings = self.by_uid("intruder_many_vuln.json")
        self.assertEqual(8.1, findings["500001"].cvssv3_score)
        # This occurrence has no score of its own, so the issue's stands in.
        self.assertEqual(7.4, findings["500002"].cvssv3_score)

    def test_snoozing_is_how_intruder_records_triage(self):
        """
        A snoozed occurrence is inactive, and the reason decides which DefectDojo flag it sets.

        An unrecognised reason leaves it inactive with neither flag: it is still triaged, just not in
        a way DefectDojo has a field for - and guessing would misreport the reviewer's decision.
        """
        findings = self.by_uid("intruder_many_vuln.json")

        self.assertTrue(findings["500001"].active)
        self.assertFalse(findings["500001"].false_p)
        self.assertFalse(findings["500001"].risk_accepted)

        self.assertFalse(findings["500002"].active)
        self.assertTrue(findings["500002"].false_p)

        self.assertFalse(findings["500003"].active)
        self.assertTrue(findings["500003"].risk_accepted)

        # A mitigating control is an accepted risk too.
        self.assertFalse(findings["500004"].active)
        self.assertTrue(findings["500004"].risk_accepted)

        self.assertFalse(findings["500005"].active)
        self.assertFalse(findings["500005"].false_p)
        self.assertFalse(findings["500005"].risk_accepted)

    def test_extra_information_is_listed_in_sorted_key_order(self):
        """
        The connector sorts because a Go map has no order.

        Matching that keeps the two import paths byte-identical rather than differing by whatever
        order the JSON happened to use.
        """
        finding = self.by_uid("intruder_many_vuln.json")["500001"]
        self.assertIn(
            "* **chain:** complete\n* **expires:** 2024-07-20\n* **issuer:** Example CA",
            finding.description,
        )

    def test_the_description_prefers_the_display_address(self):
        """
        The display address is what a person recognises; the target is what was scanned.

        So the description shows the display address while the endpoint records the target.
        """
        finding = self.by_uid("intruder_many_vuln.json")["500001"]
        self.assertIn("* **Target:** app.example.com (production)", finding.description)
        self.assertEqual("app.example.com", self.get_unsaved_locations(finding)[0].host)

    def test_an_issue_with_no_description_has_no_description_section(self):
        finding = self.by_uid("intruder_many_vuln.json")["500005"]
        self.assertNotIn("### Description", finding.description)
        self.assertIn("* **Target:** legacy.example.com", finding.description)

    def test_cves_come_from_the_occurrence_then_the_issue_prose(self):
        findings = self.by_uid("intruder_many_vuln.json")
        # The occurrence lists the CVE twice and the issue text names another.
        self.assertEqual(["CVE-2000-0001", "CVE-2000-0009"], findings["500001"].unsaved_vulnerability_ids)
        self.assertEqual(["CVE-2000-0009"], findings["500002"].unsaved_vulnerability_ids)

    def test_a_finding_with_no_identifiers_has_none(self):
        finding = self.by_uid("intruder_many_vuln.json")["500003"]
        self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_a_port_of_zero_is_not_recorded(self):
        """Intruder writes "0" when it has no port, and port zero is not a real port."""
        finding = self.by_uid("intruder_many_vuln.json")["500003"]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual("shop.example.com", locations[0].host)
        self.assertIsNone(locations[0].port)

    def test_an_ip_target_is_accepted_as_a_host(self):
        finding = self.by_uid("intruder_many_vuln.json")["500002"]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual("10.0.0.11", locations[0].host)
        self.assertEqual(8443, locations[0].port)

    def test_a_target_that_cannot_be_a_host_is_not_recorded(self):
        """
        An Intruder target can be a label rather than an address.

        DefectDojo's host field would reject it, and a ValidationError fails the whole import rather
        than the one finding, so the endpoint is dropped. The target is still in the description and
        the tags.
        """
        finding = self.by_uid("intruder_many_vuln.json")["500004"]
        self.assertEqual([], self.get_unsaved_locations(finding))
        self.assertIn("* **Target:** Reception Desk PC", finding.description)
        self.assertIn("target:Reception Desk PC", finding.unsaved_tags)

    def test_an_unparseable_first_seen_keeps_the_default_date(self):
        finding = self.by_uid("intruder_many_vuln.json")["500003"]
        self.assertEqual(datetime.now(tz=UTC).date(), finding.date)

    def test_a_bare_list_of_issues_is_accepted(self):
        findings = self.parse_string([
            {"id": 1, "title": "An issue", "severity": "high",
             "occurrences": [{"occurrence_id": 1, "target": "app.example.com"}]},
        ])
        self.assertEqual(1, len(findings))

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("Intruder", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("results", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"results": [
            "not an object",
            None,
            {"id": 1, "title": "An issue", "severity": "high",
             "occurrences": ["not an object", {"occurrence_id": 1, "target": "app.example.com"}]},
        ]})
        self.assertEqual(1, len(findings))

    def test_severity_is_always_a_known_value(self):
        for filename in ("intruder_many_vuln.json", "intruder_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
