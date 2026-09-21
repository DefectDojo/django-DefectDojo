import io
import json
from datetime import UTC, datetime

from dojo.models import Finding, Test
from dojo.tools.insightappsec.parser import InsightAppSecParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestInsightAppSecParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("insightappsec") / filename
        with path.open(encoding="utf-8") as file:
            return list(InsightAppSecParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(InsightAppSecParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the InsightAppSec connector's ScanTypeName verbatim.

        Any drift and someone who uploads an export and also syncs the API gets two un-deduplicated
        copies of every finding.
        """
        parser = InsightAppSecParser()
        self.assertEqual(["Rapid7 InsightAppSec - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "Rapid7 InsightAppSec - Connectors Import",
            parser.get_label_for_scan_types("Rapid7 InsightAppSec - Connectors Import"),
        )

    def test_the_dedupe_hash_is_the_unique_id_alone(self):
        """
        This scan type hashes the unique id and NOTHING else - no title, no severity.

        InsightAppSec's vulnerability id is stable across scans, so it is the whole identity, and
        adding a volatile field would split a finding that had merely been regraded.
        """
        self.assertEqual(["unique_id_from_tool"], InsightAppSecParser().get_dedupe_fields())

    def test_no_vuln(self):
        """
        Every row here is one Rapid7 has closed out: remediated, duplicate, false positive, ignored.

        Importing them would resurrect findings a reimport is supposed to close.
        """
        self.assertEqual(0, len(self.parse("insightappsec_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("insightappsec_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's finding_converter."""
        findings = self.parse("insightappsec_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual('Cross-Site Scripting (XSS) in "q" parameter', finding.title)
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("InsightAppSec assigned severity **HIGH**.", finding.severity_justification)
        self.assertEqual("11111111-1111-1111-1111-111111111111", finding.unique_id_from_tool)
        self.assertEqual("Cross-Site Scripting (XSS)", finding.vuln_id_from_tool)
        self.assertEqual(6.1, finding.cvssv3_score)
        self.assertEqual(datetime(2024, 7, 1, tzinfo=UTC).date(), finding.date)
        self.assertFalse(finding.static_finding)
        self.assertTrue(finding.dynamic_finding)

        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("app.example.com", locations[0].host)
        self.assertEqual("search", locations[0].path)

    def test_status_is_matched_case_sensitively(self):
        """
        The connector compares against its own uppercase constants, so casing matters.

        A lowercase "verified" is not a status InsightAppSec sends, and treating it as one would be
        this parser inventing tolerance the API path does not have.
        """
        for status, imported in (("VERIFIED", 1), ("UNREVIEWED", 1), ("verified", 0),
                                 ("REMEDIATED", 0), ("", 0)):
            with self.subTest(status=status):
                findings = self.parse_string({"data": [
                    {"id": "vuln-1", "severity": "HIGH", "status": status, "root_cause": {}},
                ]})
                self.assertEqual(imported, len(findings))

    def test_severity_enum_is_matched_case_sensitively(self):
        for label, expected in (("CRITICAL", "Critical"), ("HIGH", "High"), ("MEDIUM", "Medium"),
                                ("LOW", "Low"), ("INFORMATIONAL", "Info"), ("SAFE", "Info"),
                                ("critical", "Info"), ("not-an-enum", "Info"), ("", "Info")):
            with self.subTest(label=label):
                findings = self.parse_string({"data": [
                    {"id": "vuln-1", "severity": label, "status": "VERIFIED", "root_cause": {}},
                ]})
                self.assertEqual(expected, findings[0].severity)

    def test_the_raw_label_is_kept_as_the_justification(self):
        """An unrecognised label lands as Info, but the original is recorded so a regrade is auditable."""
        finding = self.by_uid("insightappsec_many_vuln.json")["33333333-3333-3333-3333-333333333333"]
        self.assertEqual("Info", finding.severity)
        self.assertEqual("InsightAppSec assigned severity **not-an-enum**.", finding.severity_justification)

    def test_many_vuln(self):
        """Six rows, three of them closed out by Rapid7."""
        self.assertEqual(3, len(self.parse("insightappsec_many_vuln.json")))

    def test_the_title_comes_from_the_attack_module(self):
        """
        InsightAppSec names a vulnerability only by its module id, so the readable name is a second
        call. Without it there is nothing to call the finding but a constant.
        """
        findings = self.by_uid("insightappsec_many_vuln.json")
        self.assertEqual("SQL Injection", findings["22222222-2222-2222-2222-222222222222"].title)

        without_modules = self.parse_string({"data": [
            {"id": "vuln-1", "severity": "HIGH", "status": "VERIFIED", "root_cause": {},
             "variances": [{"module": {"id": "module-xss"}}]},
        ]})
        self.assertEqual("InsightAppSec finding", without_modules[0].title)

    def test_the_parameter_is_quoted_in_the_title(self):
        """A parameter called "id" is otherwise indistinguishable from prose."""
        findings = self.parse_string({
            "data": [{"id": "vuln-1", "severity": "HIGH", "status": "VERIFIED",
                      "root_cause": {"parameter": "id"}, "variances": [{"module": {"id": "m1"}}]}],
            "modules": [{"id": "m1", "name": "SQL Injection"}],
        })
        self.assertEqual('SQL Injection in "id" parameter', findings[0].title)

    def test_the_rule_id_falls_back_from_name_to_module_id_to_vulnerability_id(self):
        findings = self.by_uid("insightappsec_many_vuln.json")
        self.assertEqual("Cross-Site Scripting (XSS)", findings["11111111-1111-1111-1111-111111111111"].vuln_id_from_tool)
        # No module metadata for this one, so the module id stands in.
        self.assertEqual("module-unknown", findings["33333333-3333-3333-3333-333333333333"].vuln_id_from_tool)

        no_variances = self.parse_string({"data": [
            {"id": "vuln-9", "severity": "HIGH", "status": "VERIFIED", "root_cause": {}},
        ]})
        self.assertEqual("vuln-9", no_variances[0].vuln_id_from_tool)

    def test_only_a_v3_vector_yields_a_v3_score(self):
        """
        InsightAppSec also reports CVSS v2 vectors, and the same number means different things on the
        two scales, so a v2 base must not land in the v3 field.
        """
        findings = self.by_uid("insightappsec_many_vuln.json")
        self.assertEqual(6.1, findings["11111111-1111-1111-1111-111111111111"].cvssv3_score)
        self.assertIsNone(findings["22222222-2222-2222-2222-222222222222"].cvssv3_score)

    def test_a_zero_score_is_not_recorded(self):
        findings = self.parse_string({"data": [
            {"id": "vuln-1", "severity": "HIGH", "status": "VERIFIED", "root_cause": {},
             "vector_string": "CVSS:3.1/AV:N", "vulnerability_score": 0},
        ]})
        self.assertIsNone(findings[0].cvssv3_score)

    def test_the_description_flattens_the_evidence(self):
        """
        The evidence is the application's own response to an attack payload.

        It is the least trustworthy text in the export, so every value is flattened to inert text -
        script content dropped, tags removed, the result HTML-escaped the way Go's EscapeString does.
        """
        finding = self.parse("insightappsec_one_vuln.json")[0]
        self.assertIn("**URL:** GET https://app.example.com/search", finding.description)
        self.assertIn("**Parameter:** q", finding.description)
        # The module prose is flattened and its script content dropped.
        self.assertIn("The application reflects input into the response without encoding.", finding.description)
        self.assertNotIn("alert('x')", finding.description)
        self.assertNotIn("<p>", finding.description)
        # Whatever survives flattening is escaped, never rendered. Go's EscapeString spells the
        # apostrophe &#39;, not Python's &#x27;.
        self.assertIn("- Attack value: &#39;&#34;&gt;\n", finding.description)
        self.assertNotIn("&#x27;", finding.description)
        self.assertNotIn("<img", finding.description)
        # Proof is flattened too.
        self.assertIn("- Proof: Reflected in the body", finding.description)

    def test_a_markup_only_attack_payload_flattens_to_nothing(self):
        """
        The connector's sanitiser drops tags and the contents of script elements.

        So an attack value that is *only* markup - "<script>alert(1)</script>" - leaves an empty
        Attack value line: the label is written because the raw value was non-empty, but nothing
        survives flattening. Mirrored rather than corrected, and raised in the PR as a follow-up for
        both sides, since the payload is the part of the evidence a reviewer most wants to see.
        """
        finding = self.parse("insightappsec_one_vuln.json")[0]
        self.assertIn("- Attack value: \n", finding.description)
        self.assertNotIn("alert(1)", finding.description)

    def test_only_three_evidence_entries_are_printed(self):
        """
        A vulnerability can carry hundreds of variances, and the connector prints three then counts
        the rest - the description is context, not an evidence archive.
        """
        finding = self.parse("insightappsec_one_vuln.json")[0]
        self.assertEqual(3, finding.description.count("**Evidence:**"))
        self.assertIn("_(2 further evidence entries omitted)_", finding.description)
        self.assertNotIn("Fifth.", finding.description)

    def test_no_omission_note_when_there_are_three_or_fewer(self):
        finding = self.by_uid("insightappsec_many_vuln.json")["22222222-2222-2222-2222-222222222222"]
        self.assertEqual(1, finding.description.count("**Evidence:**"))
        self.assertNotIn("further evidence entries omitted", finding.description)

    def test_references_are_the_ui_link_then_the_module_links_in_key_order(self):
        """
        The connector sorts the reference keys because a Go map has no order.

        Matching that keeps the two import paths byte-identical rather than differing by whatever
        order the JSON happened to use.
        """
        finding = self.parse("insightappsec_one_vuln.json")[0]
        self.assertEqual(
            "https://insight.example.com/vm/app-0001/vuln/11111111\n"
            "https://cwe.example.com/79\n"
            "https://owasp.example.com/xss",
            finding.references,
        )

    def test_a_finding_with_no_links_has_empty_references(self):
        finding = self.by_uid("insightappsec_many_vuln.json")["33333333-3333-3333-3333-333333333333"]
        self.assertEqual("", finding.references)

    def test_module_metadata_may_be_a_list_or_a_map(self):
        """The metadata comes from a call per module, so an export keys it either way."""
        vulnerability = {"id": "vuln-1", "severity": "HIGH", "status": "VERIFIED",
                         "root_cause": {"parameter": "q"}, "variances": [{"module": {"id": "m1"}}]}
        for modules in ([{"id": "m1", "name": "SQL Injection"}],
                        {"m1": {"id": "m1", "name": "SQL Injection"}},
                        {"data": [{"id": "m1", "name": "SQL Injection"}]}):
            with self.subTest(shape=type(modules).__name__):
                findings = self.parse_string({"data": [vulnerability], "modules": modules})
                self.assertEqual('SQL Injection in "q" parameter', findings[0].title)

    def test_the_date_is_the_first_ten_characters_of_the_discovery_timestamp(self):
        findings = self.by_uid("insightappsec_many_vuln.json")
        self.assertEqual(datetime(2024, 6, 1, tzinfo=UTC).date(), findings["22222222-2222-2222-2222-222222222222"].date)

    def test_a_row_with_no_discovery_date_keeps_the_default(self):
        findings = self.parse_string({"data": [
            {"id": "vuln-1", "severity": "HIGH", "status": "VERIFIED", "root_cause": {}},
        ]})
        self.assertEqual(datetime.now(tz=UTC).date(), findings[0].date)

    def test_a_bare_list_of_vulnerabilities_is_accepted(self):
        findings = self.parse_string([
            {"id": "vuln-1", "severity": "HIGH", "status": "VERIFIED", "root_cause": {}},
        ])
        self.assertEqual(1, len(findings))

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("InsightAppSec", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("data", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"data": [
            "not an object",
            None,
            {"id": "vuln-1", "severity": "HIGH", "status": "VERIFIED", "root_cause": {},
             "variances": ["not an object", {"module": {"id": "m1"}}]},
        ]})
        self.assertEqual(1, len(findings))

    def test_severity_is_always_a_known_value(self):
        for filename in ("insightappsec_many_vuln.json", "insightappsec_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
