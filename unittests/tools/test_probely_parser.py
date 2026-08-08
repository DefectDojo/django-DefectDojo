import io
import json

from dojo.models import Finding, Test
from dojo.tools.probely.parser import ProbelyParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestProbelyParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("probely") / filename).open(encoding="utf-8") as file:
            return list(ProbelyParser().get_findings(file, Test()))

    def by_uid(self, filename):
        return {f.unique_id_from_tool: f for f in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Probely connector's ScanType() verbatim.

        Note it does NOT follow the "<Vendor> - Connectors Import" pattern the other connector scan
        types use, so it cannot be derived - it has to be copied. Any drift and a customer who
        uploads an export and also syncs the API gets two un-deduplicated copies of every finding.
        """
        parser = ProbelyParser()
        self.assertEqual(["Probely API Import"], parser.get_scan_types())
        self.assertEqual("Probely API Import", parser.get_label_for_scan_types("Probely API Import"))
        self.assertNotIn("Probely - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("probely_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("probely_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring ConvertFinding in the connector's converter."""
        findings = self.parse("probely_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("SQL Injection", finding.title)
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("9001", finding.unique_id_from_tool)
        self.assertEqual("sql-injection", finding.vuln_id_from_tool)
        self.assertEqual(9.1, finding.cvssv3_score)
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", finding.cvssv3)
        self.assertEqual(89, finding.cwe)
        # Probely is DAST.
        self.assertFalse(finding.static_finding)
        self.assertTrue(finding.dynamic_finding)

        self.assertIn("**Path:** /search", finding.description)
        self.assertIn("**Method:** GET", finding.description)
        self.assertIn("The application builds a database query", finding.description)
        self.assertIn("**Evidence:**", finding.description)
        self.assertIn("produced a database error", finding.description)

    def test_the_severity_integers_are_the_connectors(self):
        """
        Probely reports severity as an integer, and only 10, 20 and 30 exist.

        Treating the number as a CVSS-like score, or as an index, would misgrade everything.
        """
        findings = self.by_uid("probely_many_vuln.json")
        self.assertEqual("High", findings["9001"].severity)    # 30
        self.assertEqual("Medium", findings["9002"].severity)  # 20
        self.assertEqual("Low", findings["9003"].severity)     # 10
        self.assertEqual("Info", findings["9004"].severity)    # 99, unrecognised

    def test_the_severity_mapping_directly(self):
        parser = ProbelyParser()
        for raw, expected in [(10, "Low"), (20, "Medium"), (30, "High"),
                              (0, "Info"), (99, "Info"), (None, "Info"), ("nonsense", "Info")]:
            self.assertEqual(expected, parser.severity({"severity": raw}), raw)
        # Probely sends integers, but a string digit must not silently become Info.
        self.assertEqual("High", parser.severity({"severity": "30"}))

    def test_closed_out_findings_are_not_imported(self):
        """
        Probely records fixed, invalid and accepted findings, and the connector skips all three.

        Importing them would put resolved and triaged work back in front of the team.
        """
        uids = set(self.by_uid("probely_many_vuln.json"))
        self.assertNotIn("9005", uids)  # fixed
        self.assertNotIn("9006", uids)  # accepted
        self.assertNotIn("9007", uids)  # invalid
        self.assertEqual(4, len(uids))

    def test_a_finding_being_retested_is_still_imported(self):
        """
        The connector deliberately does NOT skip "retesting".

        A re-test means the issue is still being worked on, so it is assumed open. Skipping it would
        drop live findings whenever somebody clicked re-test.
        """
        findings = self.by_uid("probely_many_vuln.json")
        self.assertIn("9002", findings)
        self.assertEqual("Missing Content-Security-Policy", findings["9002"].title)

    def test_the_ignored_state_check_directly(self):
        parser = ProbelyParser()
        for state in ("fixed", "invalid", "accepted", "FIXED", " accepted "):
            self.assertTrue(parser.is_ignored({"state": state}), state)
        for state in ("notfixed", "retesting", "", None):
            self.assertFalse(parser.is_ignored({"state": state}), state)

    def test_the_scanned_origin_is_recorded(self):
        """
        This scan type's deduplication hashes the ENDPOINTS.

        So an unpopulated endpoint would leave the hash computed over nothing, and every rescan would
        reimport. Asserted through get_unsaved_locations so it passes in both
        V3_FEATURE_LOCATIONS modes.
        """
        finding = self.parse("probely_one_vuln.json")[0]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("app.example.com", locations[0].host)
        self.assertEqual("https", locations[0].protocol)

    def test_endpoints_is_in_the_dedupe_fields_so_it_must_be_populated(self):
        """Guards the pairing above: if endpoints leaves the field set, the assertion above matters."""
        self.assertIn("endpoints", ProbelyParser().get_dedupe_fields())

    def test_an_explicit_port_is_carried_through(self):
        finding = self.by_uid("probely_many_vuln.json")["9003"]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("app.example.com", locations[0].host)
        self.assertEqual(8443, locations[0].port)

    def test_an_unparseable_url_records_no_endpoint_rather_than_failing(self):
        finding = self.by_uid("probely_many_vuln.json")["9004"]
        self.assertEqual([], self.get_unsaved_locations(finding))

    def test_the_insertion_point_becomes_a_readable_label(self):
        """
        The connector title-cases the insertion point and then fixes the acronyms.

        Naive title casing gives "Url Query" and "Json Body", which reads as a bug.
        """
        findings = self.by_uid("probely_many_vuln.json")
        self.assertIn("**URL Query:** q", findings["9001"].description)
        self.assertIn("**JSON Body:** session", findings["9003"].description)
        self.assertIn("**GraphQL Variable:**", findings["9004"].description)

    def test_a_finding_with_no_insertion_point_has_no_parameter_line(self):
        finding = self.by_uid("probely_many_vuln.json")["9002"]
        self.assertNotIn("**URL", finding.description)
        # No method either, so no method line.
        self.assertNotIn("**Method:**", finding.description)

    def test_the_severity_justification_mirrors_the_converters_sentence(self):
        finding = self.parse("probely_one_vuln.json")[0]
        self.assertEqual(
            "Probely has issued a severity level of **High** from a base CVSS score of **9.1**.\n"
            "*CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N*",
            finding.severity_justification,
        )

    def test_mitigation_joins_the_fix_and_the_extra_notes(self):
        """The converter concatenates them with a newline, even when one is empty."""
        finding = self.parse("probely_one_vuln.json")[0]
        self.assertEqual(
            "Use parameterised queries instead of string concatenation.\n"
            "Confirmed against the staging target only.",
            finding.mitigation,
        )
        # An empty extra still leaves the trailing newline, as the converter does.
        self.assertEqual(
            "Add a Content-Security-Policy header.\n",
            self.by_uid("probely_many_vuln.json")["9002"].mitigation,
        )

    def test_a_cwe_that_is_not_prefixed_leaves_the_cwe_at_zero(self):
        finding = self.by_uid("probely_many_vuln.json")["9004"]
        self.assertEqual(0, finding.cwe)

    def test_the_cwe_parse_directly(self):
        parser = ProbelyParser()
        self.assertEqual(89, parser.cwe({"cwe_id": "CWE-89"}))
        self.assertEqual(1004, parser.cwe({"cwe_id": "CWE-1004"}))
        self.assertEqual(0, parser.cwe({"cwe_id": "89"}))
        self.assertEqual(0, parser.cwe({"cwe_id": "CWE-abc"}))
        self.assertEqual(0, parser.cwe({}))

    def test_a_bare_array_is_accepted(self):
        report = io.StringIO(json.dumps([{
            "id": 1, "severity": 30, "state": "notfixed",
            "definition": {"id": "d", "name": "A finding", "desc": ""},
            "url": "https://app.example.com/", "path": "/",
        }]))
        findings = list(ProbelyParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("A finding", findings[0].title)

    def test_a_repeated_finding_id_collapses(self):
        row = {"id": 1, "severity": 30, "state": "notfixed",
               "definition": {"id": "d", "name": "A finding", "desc": ""}}
        report = io.StringIO(json.dumps({"results": [row, row]}))
        self.assertEqual(1, len(list(ProbelyParser().get_findings(report, Test()))))

    def test_an_unexpected_shape_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(ProbelyParser().get_findings(io.StringIO('"nope"'), Test()))
        self.assertIn("results", str(raised.exception))
