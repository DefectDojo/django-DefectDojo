import io
import json
from datetime import UTC, datetime

from dojo.models import Finding, Test
from dojo.tools.klocwork.parser import KlocworkParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestKlocworkParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("klocwork") / filename).open(encoding="utf-8") as file:
            return list(KlocworkParser().get_findings(file, Test()))

    def parse_text(self, text):
        return list(KlocworkParser().get_findings(io.StringIO(text), Test()))

    def parse_lines(self, *rows):
        return self.parse_text("\n".join(json.dumps(row) for row in rows) + "\n")

    def row(self, **overrides):
        row = {"id": 1, "name": "A finding", "code": "ABV.GENERAL", "file": "src/a.c", "line": 10,
               "severityCode": 1, "status": "Analyze"}
        row.update(overrides)
        return row

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Klocwork connector's ScanTypeName verbatim.

        Note it does NOT follow the "<Vendor> - Connectors Import" pattern the other connector scan
        types use, so it cannot be derived - it has to be copied.
        """
        parser = KlocworkParser()
        self.assertEqual(["Klocwork Scan"], parser.get_scan_types())
        self.assertEqual("Klocwork Scan", parser.get_label_for_scan_types("Klocwork Scan"))
        self.assertNotIn("Klocwork - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        """A response carrying only the run summary has no issues in it."""
        self.assertEqual(0, len(self.parse("klocwork_no_vuln.ndjson")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("klocwork_one_vuln.ndjson")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's finding_converter."""
        findings = self.parse("klocwork_one_vuln.ndjson")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("ABV.GENERAL: Buffer overflow in strcpy call", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("klocwork-100001", finding.unique_id_from_tool)
        self.assertEqual("ABV.GENERAL", finding.vuln_id_from_tool)
        self.assertEqual("src/parser/input.c", finding.file_path)
        self.assertEqual(142, finding.line)
        self.assertEqual(datetime(2024, 7, 1, tzinfo=UTC).date(), finding.date)
        self.assertTrue(finding.active)
        self.assertFalse(finding.false_p)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(["CWE", "ABV.GENERAL", "Critical"], finding.unsaved_tags)
        self.assertIn("klocwork.example.com", finding.references)

        self.assertEqual(
            "**Message:** Buffer 'dest' of size 64 may overflow.\n"
            "**Checker:** ABV.GENERAL\n"
            "**Method:** parse_input\n"
            "**Taxonomy:** CWE\n"
            "**Status:** Analyze",
            finding.description,
        )

    def test_ndjson_is_the_wire_shape(self):
        """
        Klocwork's search endpoint answers with one JSON object per line, not an array.

        That is what a saved export looks like, so it is what the parser reads first - calling
        json.load on it would fail on the second line.
        """
        self.assertEqual(5, len(self.parse("klocwork_many_vuln.ndjson")))

    def test_a_reshaped_json_array_is_also_accepted(self):
        """Somebody may have wrapped the lines into an array before saving them."""
        from_ndjson = self.by_uid("klocwork_many_vuln.ndjson")
        from_array = self.by_uid("klocwork_many_vuln.json")
        self.assertEqual(set(from_ndjson), set(from_array))
        self.assertEqual(
            from_ndjson["klocwork-100001"].description,
            from_array["klocwork-100001"].description,
        )

    def test_the_summary_line_is_not_an_issue(self):
        """
        The response ends with a line describing the run rather than a finding.

        The connector skips it by testing for the "summary" key rather than by parsing it, and so does
        this parser.
        """
        findings = self.parse_text(
            json.dumps({"summary": {"total": 1, "build": "last"}}) + "\n"
            + json.dumps(self.row()) + "\n",
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("klocwork-1", findings[0].unique_id_from_tool)

    def test_blank_and_unparseable_lines_are_skipped(self):
        findings = self.parse_text(
            "\n"
            "not json at all\n"
            "{ this line does not parse\n"
            + json.dumps(self.row()) + "\n"
            "\n",
        )
        self.assertEqual(1, len(findings))

    def test_a_row_with_no_id_is_skipped(self):
        """The id is the whole identity, so a row without one cannot be reported."""
        findings = self.by_uid("klocwork_many_vuln.ndjson")
        self.assertNotIn("klocwork-0", findings)

    def test_severity_code_one_is_the_most_severe(self):
        """
        Klocwork's severity code is the inverse of a score - 1 is Critical, not trivial.

        Reading it as a score would invert the entire ladder. Codes 5-10 are its informational tiers.
        """
        for code, expected in ((1, "Critical"), (2, "High"), (3, "Medium"), (4, "Low"),
                               (5, "Info"), (7, "Info"), (10, "Info"), (0, "Info")):
            with self.subTest(code=code):
                findings = self.parse_lines(self.row(severityCode=code))
                self.assertEqual(expected, findings[0].severity)

    def test_numbers_may_arrive_quoted(self):
        """
        Klocwork's numeric typing is modelled rather than confirmed, and the connector's own decoder
        silently skips a line it cannot parse - so a server quoting its numerics would produce a clean,
        empty sync. Both forms are accepted here for the same reason.
        """
        finding = self.by_uid("klocwork_many_vuln.ndjson")["klocwork-100002"]
        self.assertEqual("High", finding.severity)
        self.assertEqual(88, finding.line)

    def test_triage_statuses_are_false_positives(self):
        """
        "Ignore", "Not a problem" and "Filter" are all a reviewer saying it is not real.

        The deferred states the connector's query selects stay active - a deferred finding is still a
        finding.
        """
        for status, false_p in (("Ignore", True), ("Not a problem", True), ("Filter", True),
                                ("ignore", True), ("Analyze", False), ("Fix", False),
                                ("Defer", False), ("Fix in Next Release", False), ("", False)):
            with self.subTest(status=status):
                findings = self.parse_lines(self.row(status=status))
                self.assertEqual(false_p, findings[0].false_p)
                self.assertEqual(not false_p, findings[0].active)

    def test_a_deferred_finding_stays_active(self):
        finding = self.by_uid("klocwork_many_vuln.ndjson")["klocwork-100005"]
        self.assertTrue(finding.active)
        self.assertFalse(finding.false_p)

    def test_the_file_path_and_checker_are_both_in_the_hash(self):
        """The same checker firing in two files is two findings."""
        self.assertEqual(
            ["title", "severity", "file_path", "vuln_id_from_tool"],
            KlocworkParser().get_dedupe_fields(),
        )
        findings = self.by_uid("klocwork_many_vuln.ndjson")
        self.assertEqual("src/parser/input.c", findings["klocwork-100001"].file_path)
        self.assertEqual("src/cli/main.c", findings["klocwork-100002"].file_path)

    def test_title_falls_back_through_the_checker_then_the_id(self):
        by_name = self.parse_lines(self.row(code=""))
        self.assertEqual("A finding", by_name[0].title)

        by_code = self.parse_lines(self.row(name=""))
        self.assertEqual("ABV.GENERAL", by_code[0].title)

        bare = self.by_uid("klocwork_many_vuln.ndjson")["klocwork-100004"]
        self.assertEqual("Klocwork issue 100004", bare.title)
        self.assertIsNone(bare.vuln_id_from_tool)

    def test_dates_are_unix_milliseconds(self):
        """Reading them as seconds would date every finding in 1970."""
        findings = self.by_uid("klocwork_many_vuln.ndjson")
        self.assertEqual(datetime(2024, 7, 1, tzinfo=UTC).date(), findings["klocwork-100001"].date)
        self.assertEqual(datetime(2024, 6, 1, tzinfo=UTC).date(), findings["klocwork-100002"].date)

    def test_a_row_with_no_date_keeps_the_default(self):
        finding = self.by_uid("klocwork_many_vuln.ndjson")["klocwork-100003"]
        self.assertEqual(datetime.now(tz=UTC).date(), finding.date)

    def test_a_row_with_no_url_has_no_references(self):
        finding = self.by_uid("klocwork_many_vuln.ndjson")["klocwork-100002"]
        self.assertIsNone(finding.references)

    def test_a_single_issue_object_is_accepted(self):
        findings = self.parse_text(json.dumps(self.row()))
        self.assertEqual(1, len(findings))

    def test_an_object_with_an_issues_list_is_accepted(self):
        findings = self.parse_text(json.dumps({"issues": [self.row()]}))
        self.assertEqual(1, len(findings))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_text(json.dumps({"scanner": "something else"}))
        self.assertIn("Klocwork", str(context.exception))

    def test_text_with_no_issue_line_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_text("this file is not a Klocwork export at all\n")
        self.assertIn("Klocwork", str(context.exception))

    def test_an_empty_file_is_not_an_error(self):
        """An export written before the search ran is empty rather than malformed."""
        self.assertEqual(0, len(self.parse_text("")))

    def test_severity_is_always_a_known_value(self):
        for filename in ("klocwork_many_vuln.ndjson", "klocwork_one_vuln.ndjson"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
