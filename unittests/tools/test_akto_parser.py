import io
import json
from datetime import UTC, datetime

from dojo.models import Finding, Test
from dojo.tools.akto.parser import AktoParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestAktoParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("akto") / filename).open(encoding="utf-8") as file:
            return list(AktoParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(AktoParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def issue(self, **overrides):
        issue = {"apiCollectionId": 1, "apiUrl": "https://api.example.com/v1/thing", "apiMethod": "GET",
                 "testSubCategory": "BOLA", "testName": "A test", "severity": "HIGH", "status": "OPEN"}
        issue.update(overrides)
        return {"issueDetails": [issue]}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Akto connector's ScanTypeName verbatim.

        Note it does NOT follow the "<Vendor> - Connectors Import" pattern the other connector scan
        types use, so it cannot be derived - it has to be copied.
        """
        parser = AktoParser()
        self.assertEqual(["Akto Scan"], parser.get_scan_types())
        self.assertEqual("Akto Scan", parser.get_label_for_scan_types("Akto Scan"))
        self.assertNotIn("Akto - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("akto_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("akto_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's finding_converter."""
        findings = self.parse("akto_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Broken Object Level Authorization", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual(
            "akto-1700000001-GET-https://api.example.com/v1/users/{id}-BOLA",
            finding.unique_id_from_tool,
        )
        self.assertEqual("BOLA", finding.vuln_id_from_tool)
        self.assertEqual("GET https://api.example.com/v1/users/{id}", finding.component_name)
        self.assertEqual(639, finding.cwe)
        self.assertEqual("Check that the requested object belongs to the caller.", finding.mitigation)
        self.assertEqual(datetime(2024, 7, 1, tzinfo=UTC).date(), finding.date)
        self.assertTrue(finding.active)
        self.assertFalse(finding.false_p)
        self.assertFalse(finding.static_finding)
        self.assertTrue(finding.dynamic_finding)
        self.assertEqual(["BOLA", "OWASP API1:2023", "Authorization"], finding.unsaved_tags)
        self.assertEqual(
            "https://app.example.com/dashboard/issues/1\nhttps://owasp.example.com/api1",
            finding.references,
        )

        self.assertEqual(
            "**Endpoint:** GET https://api.example.com/v1/users/{id}\n"
            "**Description:** The endpoint returned another user's record.\n"
            "**Impact:** Any authenticated user can read every user's record.\n"
            "**Details:** Changing {id} to a second account's id returned that account's data.",
            finding.description,
        )

        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("api.example.com", locations[0].host)

    def test_many_vuln(self):
        self.assertEqual(5, len(self.parse("akto_many_vuln.json")))

    def test_the_endpoint_and_the_test_are_both_in_the_identity(self):
        """
        Akto runs every test against every endpoint it knows, so neither alone identifies a finding.

        Both are in the hash fields too: the same test against two paths is two findings, and two
        different tests against one path are as well.
        """
        findings = self.by_uid("akto_many_vuln.json")
        self.assertIn("akto-1700000001-GET-https://api.example.com/v1/users/{id}-BOLA", findings)
        self.assertIn("akto-1700000001-POST-/v1/reports-SSRF", findings)
        self.assertEqual(
            ["title", "severity", "endpoints", "vuln_id_from_tool"],
            AktoParser().get_dedupe_fields(),
        )

    def test_severity_labels(self):
        for label, expected in (("CRITICAL", "Critical"), ("HIGH", "High"), ("MEDIUM", "Medium"),
                                ("LOW", "Low"), ("high", "High"), ("INFO", "Info"),
                                ("not a label", "Info"), ("", "Info")):
            with self.subTest(label=label):
                findings = self.parse_string(self.issue(severity=label))
                self.assertEqual(expected, findings[0].severity)

    def test_status_decides_active_and_false_positive(self):
        """
        Akto records triage in the status.

        IGNORED is how a reviewer marks a false positive; FIXED means it is gone. Both are inactive,
        but only IGNORED sets the flag - "fixed" is not a judgement about whether it was real.
        """
        for status, active, false_p in (("OPEN", True, False), ("IGNORED", False, True),
                                        ("FIXED", False, False), ("ignored", False, True),
                                        ("", True, False)):
            with self.subTest(status=status):
                findings = self.parse_string(self.issue(status=status))
                self.assertEqual(active, findings[0].active)
                self.assertEqual(false_p, findings[0].false_p)

    def test_the_endpoint_is_the_component(self):
        """
        Akto has no package to report, so "<METHOD> <url>" is the component.

        That is what the component slot of this scan type's deduplication means here.
        """
        findings = self.by_uid("akto_many_vuln.json")
        self.assertEqual(
            "POST /v1/reports",
            findings["akto-1700000001-POST-/v1/reports-SSRF"].component_name,
        )

    def test_a_relative_path_is_not_recorded_as_an_endpoint(self):
        """
        Akto's apiUrl is often just a path, which is not an endpoint on its own.

        The connector skips those rather than inventing a host, and the path is still the component and
        in the description, so nothing is lost.
        """
        finding = self.by_uid("akto_many_vuln.json")["akto-1700000001-POST-/v1/reports-SSRF"]
        self.assertEqual([], self.get_unsaved_locations(finding))
        self.assertIn("**Endpoint:** POST /v1/reports", finding.description)

    def test_title_falls_back_to_the_sub_category_then_a_constant(self):
        by_subcategory = self.parse_string(self.issue(testName="", testSubCategory="BOLA"))
        self.assertEqual("BOLA", by_subcategory[0].title)

        bare = self.by_uid("akto_many_vuln.json")["akto-1700000003---"]
        self.assertEqual("Akto API-security issue", bare.title)
        self.assertIsNone(bare.vuln_id_from_tool)

    def test_a_collection_id_may_be_a_string(self):
        finding = self.by_uid("akto_many_vuln.json")["akto-1700000001-POST-/v1/reports-SSRF"]
        self.assertIn("1700000001", finding.unique_id_from_tool)

    def test_cwe_forms(self):
        for value, expected in (("CWE-639", 639), ("639", 639), ("cwe-639", 639),
                                ("not a cwe", 0), ("", 0)):
            with self.subTest(value=value):
                findings = self.parse_string(self.issue(testCwe=value))
                self.assertEqual(expected, findings[0].cwe)

    def test_identifiers_are_sorted_and_deduplicated_case_insensitively(self):
        """
        Akto's CVE field is free text - an API-security test usually has none, but a
        dependency-related one may name several, sometimes in mixed case.
        """
        finding = self.by_uid("akto_many_vuln.json")["akto-1700000001-POST-/v1/reports-SSRF"]
        self.assertEqual(["CVE-2000-0001", "CVE-2000-0002"], finding.unsaved_vulnerability_ids)

    def test_a_finding_with_no_cve_has_none(self):
        finding = self.parse("akto_one_vuln.json")[0]
        self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_dates_are_unix_seconds(self):
        findings = self.by_uid("akto_many_vuln.json")
        self.assertEqual(
            datetime(2024, 6, 1, tzinfo=UTC).date(),
            findings["akto-1700000001-POST-/v1/reports-SSRF"].date,
        )

    def test_a_zero_creation_time_keeps_the_default_date(self):
        finding = self.by_uid("akto_many_vuln.json")["akto-1700000002-GET-https://api.example.com/v1/health-INFO_DISCLOSURE"]
        self.assertEqual(datetime.now(tz=UTC).date(), finding.date)

    def test_a_bare_array_of_issues_is_accepted(self):
        findings = self.parse_string([
            {"apiCollectionId": 1, "apiUrl": "https://api.example.com/v1/thing", "apiMethod": "GET",
             "testSubCategory": "BOLA", "testName": "A test", "severity": "HIGH", "status": "OPEN"},
        ])
        self.assertEqual(1, len(findings))

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("Akto", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("issueDetails", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"issueDetails": [
            "not an object",
            None,
            {"apiCollectionId": 1, "apiUrl": "https://api.example.com/v1/thing", "apiMethod": "GET",
             "testSubCategory": "BOLA", "testName": "A test", "severity": "HIGH", "status": "OPEN"},
        ]})
        self.assertEqual(1, len(findings))

    def test_severity_is_always_a_known_value(self):
        for filename in ("akto_many_vuln.json", "akto_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
