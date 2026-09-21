import hashlib
import io
import json
from datetime import UTC, datetime

from dojo.models import Finding, Test
from dojo.tools.beagle.parser import BeagleParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestBeagleParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("beagle") / filename).open(encoding="utf-8") as file:
            return list(BeagleParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(BeagleParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def by_title(self, filename):
        return {finding.title: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Beagle Security connector's ScanType() verbatim.

        Any drift and a customer who uploads a report and also syncs the API gets two
        un-deduplicated copies of every finding.
        """
        parser = BeagleParser()
        self.assertEqual(["Beagle Security - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "Beagle Security - Connectors Import",
            parser.get_label_for_scan_types("Beagle Security - Connectors Import"),
        )
        self.assertIn("Beagle", parser.get_description_for_scan_types("Beagle Security - Connectors Import"))

    def test_no_vuln(self):
        """A report Beagle produced with nothing to report is not an error."""
        self.assertEqual(0, len(self.parse("beagle_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("beagle_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring finding() in the connector's converter."""
        findings = self.parse("beagle_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("SQL injection", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual(89, finding.cwe)
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", finding.cvssv3)
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertEqual(
            "A request parameter is concatenated into a database query.",
            finding.description.split("\n\n")[0],
        )
        self.assertIn("**Method:** POST", finding.description)
        self.assertIn("**URL:** https://app.example.com/api/report", finding.description)
        self.assertIn("**Beagle status:** Open", finding.description)
        self.assertIn("**CWE:** CWE-89", finding.description)
        self.assertEqual("Use parameterised queries.", finding.mitigation)
        self.assertEqual("SQL injection", finding.vuln_id_from_tool)
        self.assertEqual("POST", finding.param)
        self.assertTrue(finding.active)
        self.assertFalse(finding.is_mitigated)
        self.assertFalse(finding.static_finding)
        self.assertTrue(finding.dynamic_finding)
        self.assertEqual(datetime(2021, 9, 4, tzinfo=UTC).date(), finding.date)
        self.assertEqual(["beagle-security", "Critical"], finding.unsaved_tags)

    def test_api_envelope_is_accepted(self):
        """
        Beagle returns the report as a JSON *string* inside an envelope.

        A user can save either the envelope or the report body it carries, so both are read.
        """
        from_envelope = self.parse("beagle_one_vuln.json")[0]

        with (get_unit_tests_scans_path("beagle") / "beagle_one_vuln.json").open(encoding="utf-8") as file:
            envelope = json.load(file)
        from_body = self.parse_string(json.loads(envelope["result"]))[0]

        self.assertEqual(from_envelope.title, from_body.title)
        self.assertEqual(from_envelope.severity, from_body.severity)
        self.assertEqual(from_envelope.description, from_body.description)

    def test_result_may_be_a_nested_object(self):
        """An export that pretty-printed the report into the envelope instead of escaping it."""
        findings = self.parse_string({
            "code": "0",
            "result": {"url": "https://app.example.com", "vulnerabilities": [{"name": "Open redirect", "severity": "Low"}]},
        })
        self.assertEqual(1, len(findings))
        self.assertEqual("Open redirect", findings[0].title)

    def test_many_vuln(self):
        """One finding per occurrence, so five report entries with seven occurrences is six findings."""
        self.assertEqual(6, len(self.parse("beagle_many_vuln.json")))

    def test_one_finding_per_occurrence(self):
        """
        A finding reported on two URLs is two findings.

        This is the connector's vulnerabilityFindings(): an occurrence is one place the finding was
        observed, and their statuses differ, which is exactly why they are kept apart.
        """
        findings = [
            finding for finding in self.parse("beagle_many_vuln.json")
            if finding.title == "Information disclosure in HTTP headers"
        ]
        self.assertEqual(2, len(findings))

        by_endpoint = {self.get_unsaved_locations(finding)[0].path: finding for finding in findings}
        self.assertEqual({"status.asp", "login"}, set(by_endpoint))

        self.assertTrue(by_endpoint["status.asp"].active)
        self.assertFalse(by_endpoint["status.asp"].is_mitigated)
        self.assertEqual("GET", by_endpoint["status.asp"].param)

        # Beagle calls this occurrence "Fixed", so it is imported as mitigated rather than open.
        self.assertFalse(by_endpoint["login"].active)
        self.assertTrue(by_endpoint["login"].is_mitigated)
        self.assertEqual("POST", by_endpoint["login"].param)

    def test_severity_label_wins_over_score(self):
        findings = self.by_title("beagle_many_vuln.json")
        finding = findings["Information disclosure in HTTP headers"]
        self.assertEqual("Medium", finding.severity)
        # The vector was carried under "cvss", which is not a number, so no score was recorded.
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", finding.cvssv3)
        self.assertIsNone(finding.cvssv3_score)

    def test_numeric_severity_is_graded_against_the_cvss_floors(self):
        """
        A tenant that scores reports with CVSS sends a number under the severity key.

        The connector's floors are 9.0 Critical, 7.0 High, 4.0 Medium, anything else Low.
        """
        findings = self.by_title("beagle_many_vuln.json")
        self.assertEqual("High", findings["Reflected cross-site scripting"].severity)
        self.assertEqual(8.2, findings["Reflected cross-site scripting"].cvssv3_score)
        self.assertEqual("Low", findings["Beagle Security finding (215, 216)"].severity)

    def test_severity_floors(self):
        for score, expected in ((10.0, "Critical"), (9.0, "Critical"), (8.9, "High"), (7.0, "High"),
                                (6.9, "Medium"), (4.0, "Medium"), (3.9, "Low"), (0.1, "Low")):
            with self.subTest(score=score):
                findings = self.parse_string({"url": "https://app.example.com", "vulnerabilities": [
                    {"name": "Scored finding", "severity": score},
                ]})
                self.assertEqual(expected, findings[0].severity)

    def test_unrecognised_severity_label_is_info(self):
        """
        An unknown label is not a guess.

        Beagle does not publish the severity enum, so a label outside the known set is imported as
        Info rather than being mapped by resemblance - but the label itself is kept as a tag so the
        real value is not lost.
        """
        finding = self.by_title("beagle_many_vuln.json")["Missing security headers"]
        self.assertEqual("Info", finding.severity)
        self.assertEqual(["beagle-security", "Somewhat risky"], finding.unsaved_tags)

    def test_no_severity_and_no_score_is_info(self):
        findings = self.parse_string({"url": "https://app.example.com", "vulnerabilities": [
            {"name": "Unscored finding"},
        ]})
        self.assertEqual("Info", findings[0].severity)
        self.assertEqual(["beagle-security"], findings[0].unsaved_tags)

    def test_finding_with_no_occurrences_targets_the_application(self):
        """
        A finding Beagle reported without occurrences still gets one finding.

        With no occurrence there is no method or per-occurrence URL, so it is aimed at the
        application's own URL and counted as active.
        """
        finding = self.by_title("beagle_many_vuln.json")["Missing security headers"]
        self.assertTrue(finding.active)
        self.assertFalse(finding.is_mitigated)
        self.assertIsNone(finding.param)
        self.assertNotIn("**Method:**", finding.description)
        self.assertNotIn("**Beagle status:**", finding.description)

        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("app.example.com", locations[0].host)

    def test_occurrence_without_a_url_falls_back_to_the_application(self):
        finding = self.by_title("beagle_many_vuln.json")["Beagle Security finding (215, 216)"]
        self.assertEqual("HEAD", finding.param)
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("app.example.com", locations[0].host)
        self.assertEqual("https", locations[0].protocol)

    def test_endpoint_carries_scheme_port_and_path(self):
        """
        The tested URL is recorded in full.

        This scan type's deduplication hashes the endpoints, so an unpopulated endpoint would leave
        the hash computed over nothing and every rescan would reimport.
        """
        finding = self.by_title("beagle_many_vuln.json")["Outdated TLS protocol offered"]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("api.example.com", locations[0].host)
        self.assertEqual(8443, locations[0].port)
        self.assertEqual("https", locations[0].protocol)
        self.assertEqual("v1/health", locations[0].path)

    def test_every_finding_records_an_endpoint(self):
        for finding in self.parse("beagle_many_vuln.json"):
            with self.subTest(title=finding.title):
                self.assertEqual(1, len(self.get_unsaved_locations(finding)))

    def test_query_string_is_kept(self):
        finding = self.by_title("beagle_many_vuln.json")["Reflected cross-site scripting"]
        location = self.get_unsaved_locations(finding)[0]
        self.assertEqual("search", location.path)
        self.assertEqual("q=1", location.query)

    def test_field_aliases(self):
        """
        Beagle publishes none of the per-finding field names.

        The connector reads each from a set of plausible aliases, case-insensitively, and this
        parser has to accept the same spellings or the two disagree about the same report.
        """
        findings = self.by_title("beagle_alias_keys.json")
        self.assertEqual(2, len(findings))

        cookie = findings["Session cookie missing the Secure attribute"]
        self.assertEqual("Low", cookie.severity)
        self.assertEqual(614, cookie.cwe)
        self.assertEqual("A session cookie is set without the Secure attribute.", cookie.description.split("\n\n")[0])
        self.assertEqual("Set the Secure attribute on every session cookie.", cookie.mitigation)

        listing = findings["Directory listing enabled"]
        self.assertEqual("Medium", listing.severity)
        self.assertEqual(5.3, listing.cvssv3_score)
        self.assertEqual("The web server returns an index of the directory contents.", listing.description)
        self.assertEqual("Disable automatic directory indexes.", listing.mitigation)

    def test_finding_array_is_found_by_shape_when_its_name_is_unknown(self):
        """
        Beagle's reference cuts the finding array's name out of its only sample.

        The documented-plausible names are tried first, then the first key - in sorted order, so the
        choice is deterministic - whose value is an array of objects. A confirmed report key is never
        mistaken for the finding list.
        """
        findings = self.parse("beagle_alias_keys.json")
        self.assertEqual(2, len(findings))

        by_documented_name = self.parse_string({"url": "https://app.example.com", "signatures": [
            {"name": "Named array"},
        ]})
        self.assertEqual("Named array", by_documented_name[0].title)

        by_shape = self.parse_string({"url": "https://app.example.com", "some_future_key": [
            {"name": "Array found by shape"},
        ]})
        self.assertEqual("Array found by shape", by_shape[0].title)

    def test_occurrence_key_accepts_the_vendors_own_spelling(self):
        """Beagle spells it "occurences", with one "r"; the connector leads with their spelling."""
        for key in ("occurences", "occurrences", "instances"):
            with self.subTest(key=key):
                findings = self.parse_string({"url": "https://app.example.com", "vulnerabilities": [{
                    "name": "Two places",
                    "severity": "High",
                    key: [
                        {"status": "Open", "vulnerability": {"Method": "get", "Url": "https://app.example.com/a"}},
                        {"status": "Open", "vulnerability": {"Method": "get", "Url": "https://app.example.com/b"}},
                    ],
                }]})
                self.assertEqual(2, len(findings))

    def test_only_the_documented_fixed_status_mitigates(self):
        """
        "Fixed" is the one status value Beagle's documentation shows.

        The rest of the enum is unpublished, so anything else counts as open rather than being
        guessed at.
        """
        for status, mitigated in (("Fixed", True), ("fixed", True), ("FIXED", True), ("Open", False),
                                  ("Reopened", False), ("", False)):
            with self.subTest(status=status):
                findings = self.parse_string({"url": "https://app.example.com", "vulnerabilities": [{
                    "name": "Status check",
                    "occurences": [{"status": status, "vulnerability": {"Url": "https://app.example.com/a"}}],
                }]})
                self.assertEqual(mitigated, findings[0].is_mitigated)
                self.assertEqual(not mitigated, findings[0].active)

    def test_title_falls_back_to_the_cwe(self):
        finding = self.by_title("beagle_many_vuln.json")["Beagle Security finding (215, 216)"]
        self.assertEqual(215, finding.cwe)
        self.assertIsNone(finding.vuln_id_from_tool)

    def test_title_falls_back_to_a_bare_label(self):
        findings = self.parse_string({"url": "https://app.example.com", "vulnerabilities": [{"score": 5.0}]})
        self.assertEqual("Beagle Security finding", findings[0].title)
        self.assertEqual(0, findings[0].cwe)

    def test_cwe_forms(self):
        """A CWE id arrives as "CWE-215", a bare number, a list, or a comma-separated string."""
        for value, expected in (("CWE-215", 215), ("215", 215), (215, 215), ("cwe-215", 215),
                                ("215, 216", 215), (["CWE-693", "CWE-1021"], 693), ("CWE-79 CWE-80", 79),
                                ("not a cwe", 0), ("", 0), ("CWE-0", 0), ("-5", 0)):
            with self.subTest(value=value):
                findings = self.parse_string({"url": "https://app.example.com", "vulnerabilities": [
                    {"name": "CWE check", "cwe": value},
                ]})
                self.assertEqual(expected, findings[0].cwe)

    def test_report_date_prefers_generated_then_approved(self):
        """The connector stamps every finding in a report with the report's own date."""
        for report, expected in (
            ({"generated_date": "04 Sep 2021", "approved_date": "05 Sep 2021"}, datetime(2021, 9, 4, tzinfo=UTC).date()),
            ({"approved_date": "05 Sep 2021"}, datetime(2021, 9, 5, tzinfo=UTC).date()),
        ):
            with self.subTest(report=report):
                findings = self.parse_string({**report, "vulnerabilities": [{"name": "Dated"}]})
                self.assertEqual(expected, findings[0].date)

    def test_unparseable_report_date_falls_back(self):
        """An unreadable generated date falls through to the approved date."""
        findings = self.by_title("beagle_alias_keys.json")
        self.assertEqual(
            datetime(2022, 1, 12, tzinfo=UTC).date(),
            findings["Session cookie missing the Secure attribute"].date,
        )

    def test_missing_report_date_is_today(self):
        findings = self.parse_string({"url": "https://app.example.com", "vulnerabilities": [{"name": "Undated"}]})
        self.assertEqual(datetime.now(tz=UTC).date(), findings[0].date)

    def test_unique_id_matches_the_connector_when_the_token_is_present(self):
        """
        The connector's identity is sha256(token|name|method|url).

        An export that carries the application token gets connector-identical ids.
        """
        finding = self.parse("beagle_one_vuln.json")[0]
        expected = hashlib.sha256(
            b"example-application-token|SQL injection|POST|https://app.example.com/api/report",
        ).hexdigest()
        self.assertEqual(expected, finding.unique_id_from_tool)

    def test_no_unique_id_without_a_token(self):
        """
        A report body does not carry the application token, and no id is invented.

        This scan type deduplicates on unique_id_from_tool *or* the hash code, so leaving the id
        unset lets the hash over title, severity and endpoints match the API findings instead. An id
        hashed over a token the connector never used would match nothing.
        """
        for finding in self.parse("beagle_many_vuln.json"):
            with self.subTest(title=finding.title):
                self.assertIsNone(finding.unique_id_from_tool)

    def test_unique_ids_differ_per_occurrence(self):
        payload = {
            "applicationToken": "example-application-token",
            "url": "https://app.example.com",
            "vulnerabilities": [{
                "name": "Two places",
                "occurences": [
                    {"status": "Open", "vulnerability": {"Method": "get", "Url": "https://app.example.com/a"}},
                    {"status": "Open", "vulnerability": {"Method": "get", "Url": "https://app.example.com/b"}},
                ],
            }],
        }
        findings = self.parse_string(payload)
        self.assertEqual(2, len({finding.unique_id_from_tool for finding in findings}))

    def test_severity_is_always_a_known_value(self):
        for filename in ("beagle_many_vuln.json", "beagle_one_vuln.json", "beagle_alias_keys.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, title=finding.title):
                    self.assertIn(finding.severity, Finding.SEVERITIES)

    def test_non_object_report_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string([{"name": "A bare list of findings"}])
        self.assertIn("Beagle Security", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        """A file with neither Beagle's report keys nor a finding list is not a Beagle report."""
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else", "count": 3})
        self.assertIn("report keys", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"url": "https://app.example.com", "vulnerabilities": [
            {"name": "The one real finding"},
            "not an object",
            None,
        ]})
        self.assertEqual(1, len(findings))
        self.assertEqual("The one real finding", findings[0].title)

    def test_an_array_that_does_not_start_with_an_object_is_not_the_finding_list(self):
        """
        The shape check looks at the first element only, exactly as the connector's does.

        So an array of strings is not mistaken for the finding list - it is skipped and, with no
        other candidate in the document, the report simply has no findings.
        """
        self.assertEqual(0, len(self.parse_string({
            "url": "https://app.example.com",
            "vulnerabilities": ["not an object", {"name": "Never reached"}],
        })))

    def test_malformed_occurrence_is_tolerated(self):
        findings = self.parse_string({"url": "https://app.example.com", "vulnerabilities": [{
            "name": "Odd occurrences",
            "occurences": ["not an object", {"status": "Open", "vulnerability": "not an object"}],
        }]})
        self.assertEqual(1, len(findings))
        self.assertIsNone(findings[0].param)
        self.assertEqual("app.example.com", self.get_unsaved_locations(findings[0])[0].host)
