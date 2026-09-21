import io
import json
from datetime import date

from dojo.models import Finding, Test
from dojo.tools.ostorlab.parser import OstorlabParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestOstorlabParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("ostorlab") / filename
        with path.open(encoding="utf-8") as file:
            return list(OstorlabParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(OstorlabParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def scan(self, vuln=None, asset_type="WEB", scan_id=1):
        return {"data": {"scan": {
            "id": scan_id, "assetType": asset_type, "createdTime": "2024-06-03T09:30:00Z",
            "vulnerabilities": {"vulnerabilities": [vuln or {
                "id": 1, "detail": {"title": "A finding", "riskRating": "HIGH"}}]}}}}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Ostorlab connector's ScanTypeName verbatim.

        Note it does NOT follow the "<Vendor> - Connectors Import" pattern the other connector scan
        types use, so it cannot be derived - it has to be copied.
        """
        parser = OstorlabParser()
        self.assertEqual(["Ostorlab Scan"], parser.get_scan_types())
        self.assertEqual("Ostorlab Scan", parser.get_label_for_scan_types("Ostorlab Scan"))
        self.assertNotIn("Ostorlab - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("ostorlab_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("ostorlab_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's finding_converter."""
        findings = self.parse("ostorlab_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Application is debuggable", finding.title)
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("ostorlab-4001-900001", finding.unique_id_from_tool)
        self.assertEqual("Application is debuggable", finding.vuln_id_from_tool)
        self.assertEqual("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", finding.cvssv3)
        self.assertEqual("Set android:debuggable to false in the release manifest.",
                         finding.mitigation)
        self.assertEqual(date(2024, 6, 2), finding.date)
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertTrue(finding.active)
        # ANDROID_STORE is analysed statically.
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(["HIGH", "ANDROID_STORE"], finding.unsaved_tags)
        self.assertEqual(
            "- Vendor guidance: https://example.com/guidance/debuggable\n"
            "- https://example.com/advisories/CVE-2000-0001\n"
            "- A reference with no link",
            finding.references,
        )
        self.assertEqual(
            "**Description:**\n"
            "A debuggable release build lets anyone with the device read memory and step through "
            "the application.\n\n"
            "**Summary:**\n"
            "The release build allows a debugger to attach.\n\n"
            "**Technical detail:**\n"
            "The application ships a debuggable manifest flag.\n\n"
            "**File path:**\n"
            "AndroidManifest.xml\n\n"
            "**Code location:**\n"
            "application/@android:debuggable",
            finding.description,
        )

    def test_many_vuln(self):
        """Seven vulnerabilities, but the SECURE one is never imported."""
        self.assertEqual(6, len(self.parse("ostorlab_many_vuln.json")))

    def test_a_secure_rating_is_a_passed_check_and_is_skipped(self):
        """
        SECURE means the check passed. Importing it would file a passing check as a finding.

        That is what the connector's IsIgnored exists to prevent.
        """
        findings = self.by_uid("ostorlab_many_vuln.json")
        self.assertNotIn("ostorlab-4002-900014", findings)
        for finding in findings.values():
            self.assertNotIn("Never imported", finding.title)

    def test_secure_is_matched_case_insensitively(self):
        for rating in ("SECURE", "secure", " Secure "):
            with self.subTest(rating=rating):
                self.assertEqual(0, len(self.parse_string(self.scan(
                    vuln={"id": 1, "detail": {"title": "A finding", "riskRating": rating}}))))

    def test_risk_ratings(self):
        for rating, expected in (("CRITICAL", "Critical"), ("HIGH", "High"), ("MEDIUM", "Medium"),
                                 ("LOW", "Low"), ("POTENTIALLY", "Low"), ("HARDENING", "Info"),
                                 ("IMPORTANT", "Info"), ("INFO", "Info"), ("critical", "Critical"),
                                 ("", "Info")):
            with self.subTest(rating=rating):
                findings = self.parse_string(self.scan(
                    vuln={"id": 1, "detail": {"title": "A finding", "riskRating": rating}}))
                self.assertEqual(expected, findings[0].severity)

    def test_potentially_is_low_because_ostorlab_could_not_confirm_it(self):
        finding = self.by_uid("ostorlab_many_vuln.json")["ostorlab-4002-900011"]
        self.assertEqual("Low", finding.severity)
        self.assertIn("POTENTIALLY", finding.unsaved_tags)

    def test_an_important_rating_grades_as_info(self):
        """
        Mirrored, not corrected: the connector maps IMPORTANT to Info.

        Changing it here would make a file import disagree with an API sync of the same finding.
        Raised in the PR as a follow-up on the connector side.
        """
        finding = self.by_uid("ostorlab_many_vuln.json")["ostorlab-4002-900013"]
        self.assertEqual("Info", finding.severity)

    def test_the_asset_type_decides_static_versus_dynamic(self):
        """
        Ostorlab scans mobile binaries and web targets from one platform.

        A binary is read; a web target is exercised. Deciding per scan is what keeps both honest.
        """
        for asset_type, static in (("ANDROID_STORE", True), ("IOS_STORE", True),
                                   ("ANDROID_FILE", True), ("MOBILE_APP", True),
                                   ("WEB", False), ("NETWORK", False), ("DOMAIN_NAME", False),
                                   ("", False)):
            with self.subTest(asset_type=asset_type):
                findings = self.parse_string(self.scan(asset_type=asset_type))
                self.assertEqual(static, findings[0].static_finding)
                self.assertEqual(not static, findings[0].dynamic_finding)

    def test_a_web_scan_is_dynamic(self):
        finding = self.by_uid("ostorlab_many_vuln.json")["ostorlab-4002-900010"]
        self.assertFalse(finding.static_finding)
        self.assertTrue(finding.dynamic_finding)

    def test_identifiers_are_extracted_from_the_prose_and_the_references(self):
        """
        Ostorlab exposes NO CVE field, so a finding that names one names it in its text.

        The connector's shared extractor sorts its results, so the order is alphabetical rather than
        the order they appear - the fixture names CVE-2000-0002 before CVE-2000-0001.
        """
        finding = self.by_uid("ostorlab_many_vuln.json")["ostorlab-4002-900010"]
        self.assertEqual(["CVE-2000-0001", "CVE-2000-0002"], finding.unsaved_vulnerability_ids)

    def test_a_reference_url_alone_can_supply_an_identifier(self):
        finding = self.parse("ostorlab_one_vuln.json")[0]
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)

    def test_a_finding_naming_no_identifier_has_none(self):
        finding = self.by_uid("ostorlab_many_vuln.json")["ostorlab-4002-900012"]
        self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_non_cve_advisory_formats_are_recognised(self):
        for identifier in ("GHSA-aaaa-bbbb-cccc", "GO-2024-1234", "RHSA-2024:1234"):
            with self.subTest(identifier=identifier):
                findings = self.parse_string(self.scan(vuln={
                    "id": 1, "technicalDetail": f"see {identifier}",
                    "detail": {"title": "A finding", "riskRating": "HIGH"}}))
                self.assertEqual([identifier], findings[0].unsaved_vulnerability_ids)

    def test_the_location_metadata_is_rendered_under_its_own_type(self):
        """
        Ostorlab attaches whatever context fits the finding - a URL, a file path, a code location.

        Using the metadata type as the label means the parser does not have to know the names in
        advance, so a new kind of context still reaches the reader.
        """
        finding = self.by_uid("ostorlab_many_vuln.json")["ostorlab-4002-900010"]
        self.assertIn("**URL:**\nhttps://app.example.com/search?q=1", finding.description)

    def test_metadata_with_no_type_is_skipped(self):
        findings = self.parse_string(self.scan(vuln={
            "id": 1, "detail": {"title": "A finding", "riskRating": "HIGH"},
            "vulnerabilityLocation": {"metadata": [
                {"metadataType": "", "metadataValue": "orphaned"},
                "not an object", None,
                {"metadataType": "Kept", "metadataValue": "value"}]}}))
        self.assertIn("**Kept:**\nvalue", findings[0].description)
        self.assertNotIn("orphaned", findings[0].description)

    def test_a_finding_with_no_detail_block_still_imports(self):
        """
        The detail is a pointer in the connector, so it can be absent.

        The finding falls back to a generated title and grades as Info rather than being dropped.
        """
        finding = self.by_uid("ostorlab_many_vuln.json")["ostorlab-4002-900015"]
        self.assertEqual("Ostorlab finding 900015", finding.title)
        self.assertEqual("Info", finding.severity)
        self.assertIsNone(finding.vuln_id_from_tool)
        self.assertIsNone(finding.mitigation)
        self.assertIsNone(finding.cvssv3)
        self.assertIsNone(finding.references)
        self.assertIn("**Technical detail:**", finding.description)

    def test_the_endpoint_prefers_the_asset_name_then_its_host(self):
        findings = self.by_uid("ostorlab_many_vuln.json")
        from_host = self.get_unsaved_locations(findings["ostorlab-4002-900010"])
        self.assertEqual(1, len(from_host))
        self.assertEqual("app.example.com", from_host[0].host)

        from_name = self.get_unsaved_locations(findings["ostorlab-4002-900011"])
        self.assertEqual(1, len(from_name))
        self.assertEqual("app.example.com", from_name[0].host)

    def test_a_mobile_finding_has_no_endpoint(self):
        """A mobile scan names a package, not a host, so there is nothing to record."""
        finding = self.parse("ostorlab_one_vuln.json")[0]
        self.assertEqual(0, len(self.get_unsaved_locations(finding)))

    def test_a_host_defectdojo_would_reject_adds_no_endpoint(self):
        """
        A bad host makes Endpoint.clean() raise, which fails the WHOLE import.

        Declining to build the endpoint keeps the rest of the file importable.
        """
        finding = self.by_uid("ostorlab_many_vuln.json")["ostorlab-4002-900016"]
        self.assertEqual(0, len(self.get_unsaved_locations(finding)))
        self.assertEqual("Medium", finding.severity)

    def test_the_cvss_vector_is_a_vector_not_a_score(self):
        """Ostorlab publishes the vector string and no score, so cvssv3_score stays unset."""
        finding = self.parse("ostorlab_one_vuln.json")[0]
        self.assertTrue(finding.cvssv3.startswith("CVSS:3.1/"))
        self.assertIsNone(finding.cvssv3_score)

    def test_the_identity_spans_the_scan_and_the_vulnerability(self):
        """The same finding in two scans of one app is two records, one per scan."""
        vuln = {"id": 900010, "detail": {"title": "A finding", "riskRating": "HIGH"}}
        first = self.parse_string(self.scan(vuln=vuln, scan_id=4001))
        second = self.parse_string(self.scan(vuln=vuln, scan_id=4002))
        self.assertEqual("ostorlab-4001-900010", first[0].unique_id_from_tool)
        self.assertEqual("ostorlab-4002-900010", second[0].unique_id_from_tool)

    def test_quoted_ids_are_accepted(self):
        findings = self.parse_string({"data": {"scan": {
            "id": "4001", "assetType": "WEB",
            "vulnerabilities": {"vulnerabilities": [
                {"id": "900010", "detail": {"title": "A finding", "riskRating": "HIGH"}}]}}}})
        self.assertEqual("ostorlab-4001-900010", findings[0].unique_id_from_tool)

    def test_export_shapes(self):
        """
        Ostorlab's own shape doubles the key: the outer one is the connection, the inner one the list.

        The unwrapped forms and a bare array are accepted too.
        """
        vuln = {"id": 1, "detail": {"title": "A finding", "riskRating": "HIGH"}}
        payloads = (
            {"data": {"scan": {"id": 1, "vulnerabilities": {"vulnerabilities": [vuln]}}}},
            {"scan": {"id": 1, "vulnerabilities": {"vulnerabilities": [vuln]}}},
            {"vulnerabilities": {"vulnerabilities": [vuln]}},
            {"vulnerabilities": [vuln]},
            [vuln],
        )
        for payload in payloads:
            with self.subTest(shape=str(payload)[:26]):
                self.assertEqual(1, len(self.parse_string(payload)))

    def test_an_export_with_no_scan_context_still_imports(self):
        """
        Without the scan, the identity carries scan 0 and every finding is dynamic.

        The findings are still produced rather than dropped, and the docs say what is lost.
        """
        findings = self.parse_string([{"id": 900010,
                                       "detail": {"title": "A finding", "riskRating": "HIGH"}}])
        self.assertEqual(1, len(findings))
        self.assertEqual("ostorlab-0-900010", findings[0].unique_id_from_tool)
        self.assertFalse(findings[0].static_finding)

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("Ostorlab", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("vulnerabilities", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"data": {"scan": {"id": 1, "vulnerabilities": {
            "vulnerabilities": ["not an object", None,
                                {"id": 9, "detail": {"title": "A finding", "riskRating": "LOW",
                                                     "references": ["not an object", None]}}]}}}})
        self.assertEqual(1, len(findings))
        self.assertEqual("ostorlab-1-9", findings[0].unique_id_from_tool)
        self.assertIsNone(findings[0].references)

    def test_the_hash_includes_a_component_ostorlab_never_reports(self):
        """
        The copied hash field list names component_name, and Ostorlab reports no component.

        So that field hashes as empty and the hash is effectively title plus severity. Copied as it
        stands rather than trimmed, because changing it would change how the connector's own findings
        hash - raised in the PR as a follow-up.
        """
        self.assertEqual(["title", "severity", "component_name"],
                         OstorlabParser().get_dedupe_fields())
        for finding in self.parse("ostorlab_many_vuln.json"):
            with self.subTest(uid=finding.unique_id_from_tool):
                self.assertIsNone(finding.component_name)

    def test_severity_is_always_a_known_value(self):
        for filename in ("ostorlab_many_vuln.json", "ostorlab_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
