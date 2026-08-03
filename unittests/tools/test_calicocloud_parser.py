import io
import json
from datetime import date

from dojo.models import Finding, Test
from dojo.tools.calicocloud.parser import CalicocloudParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestCalicocloudParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("calicocloud") / filename
        with path.open(encoding="utf-8") as file:
            return list(CalicocloudParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(CalicocloudParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def row(self, **overrides):
        vuln = {"id": "CVE-2000-0001", "name": "A finding", "severity": "high",
                "package_name": "example-lib", "version": "1.0.0"}
        vuln.update(overrides)
        return {"images": [{"imageID": "img-1", "repository": "generic-app", "tag": "1.0",
                            "scan_result": "Fail", "result": "Fail", "vulnerabilities": [vuln]}]}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Calico Cloud connector's ScanTypeName verbatim.

        Note it does NOT follow the "<Vendor> - Connectors Import" pattern the other connector scan
        types use, so it cannot be derived - it has to be copied.
        """
        parser = CalicocloudParser()
        self.assertEqual(["Calico Cloud Image Assurance Scan"], parser.get_scan_types())
        self.assertEqual("Calico Cloud Image Assurance Scan",
                         parser.get_label_for_scan_types("Calico Cloud Image Assurance Scan"))
        self.assertNotIn("Calico Cloud - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("calicocloud_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("calicocloud_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's finding_converter."""
        findings = self.parse("calicocloud_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("CVE-2000-0001: Heap overflow in the example compression library",
                         finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("calico-cloud-img-0001-CVE-2000-0001", finding.unique_id_from_tool)
        self.assertEqual("CVE-2000-0001", finding.vuln_id_from_tool)
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual(9.1, finding.cvssv3_score)
        self.assertEqual("example-compress", finding.component_name)
        self.assertEqual("1.2.3", finding.component_version)
        self.assertEqual("https://example.com/advisories/CVE-2000-0001", finding.references)
        self.assertEqual("Upgrade example-compress to 1.2.4, 1.3.0.", finding.mitigation)
        self.assertEqual(date(2024, 6, 2), finding.date)
        self.assertTrue(finding.active)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

        self.assertEqual(
            "**Description:** A crafted archive can overflow a heap buffer during decompression.\n"
            "**Image:** registry.example.com/generic-app:1.4.0\n"
            "**Digest:** sha256:11111111111111111111111111111111111111111111111111111111"
            "11111111\n"
            "**Package:** example-compress\n"
            "**Installed version:** 1.2.3\n"
            "**Fixed in:** 1.2.4, 1.3.0",
            finding.description,
        )

    def test_many_vuln(self):
        """Six vulnerabilities across five images, but the pending image's one is never imported."""
        self.assertEqual(6, len(self.parse("calicocloud_many_vuln.json")))

    def test_an_image_whose_scan_is_still_unknown_is_skipped_entirely(self):
        """
        Calico says "Unknown" while a registry scan is still being processed.

        Importing those results would record a partial scan as a complete one, so the connector skips
        the image and this does too - even though the vulnerability on it is Critical.
        """
        findings = self.by_uid("calicocloud_many_vuln.json")
        self.assertNotIn("calico-cloud-img-0002-CVE-2000-0099", findings)
        for finding in findings.values():
            self.assertNotIn("Never imported", finding.title)

    def test_unknown_is_matched_case_insensitively_in_either_status_field(self):
        for key in ("scan_result", "result"):
            for value in ("Unknown", "unknown", " UNKNOWN "):
                with self.subTest(key=key, value=value):
                    payload = self.row()
                    payload["images"][0][key] = value
                    self.assertEqual(0, len(self.parse_string(payload)))

    def test_the_cvss_score_decides_the_severity_not_calicos_word(self):
        """
        The fixture's first finding is scored 9.1 but labelled "low".

        Calico's Pass/Warn/Fail verdict and its severity word are per-tenant configuration; scoring
        from CVSS is what keeps the same CVE at the same severity in every tenant.
        """
        finding = self.by_uid("calicocloud_many_vuln.json")["calico-cloud-img-0001-CVE-2000-0001"]
        self.assertEqual("Critical", finding.severity)
        self.assertEqual(9.1, finding.cvssv3_score)

    def test_the_nested_cvss_base_score_is_the_fallback_and_may_be_quoted(self):
        finding = self.by_uid("calicocloud_many_vuln.json")["calico-cloud-img-0001-CVE-2000-0002"]
        self.assertEqual(7.5, finding.cvssv3_score)
        self.assertEqual("High", finding.severity)

    def test_the_severity_word_is_used_only_when_there_is_no_score(self):
        findings = self.by_uid("calicocloud_many_vuln.json")
        unscored = findings["calico-cloud-img-0001-CALICO-2024-0003"]
        self.assertEqual(0.0, unscored.cvssv3_score)
        self.assertEqual("Medium", unscored.severity)

    def test_negligible_is_info(self):
        finding = self.by_uid("calicocloud_many_vuln.json")["calico-cloud-img-0001-CVE-2000-0004"]
        self.assertEqual("Info", finding.severity)

    def test_cvss_score_bands(self):
        cases = ((9.0, "Critical"), (9.8, "Critical"), (7.0, "High"), (8.9, "High"),
                 (4.0, "Medium"), (6.9, "Medium"), (0.1, "Low"), (3.9, "Low"))
        for score, expected in cases:
            with self.subTest(score=score):
                findings = self.parse_string(self.row(cvss3Score=score, severity="negligible"))
                self.assertEqual(expected, findings[0].severity)

    def test_severity_words(self):
        for label, expected in (("critical", "Critical"), ("high", "High"), ("medium", "Medium"),
                                ("low", "Low"), ("CRITICAL", "Critical"), ("negligible", "Info"),
                                ("unknown", "Info"), ("", "Info")):
            with self.subTest(label=label):
                findings = self.parse_string(self.row(severity=label, cvss3Score=0))
                self.assertEqual(expected, findings[0].severity)

    def test_only_a_cve_becomes_a_vulnerability_id(self):
        """Calico issues its own advisory ids too, and those are not CVEs."""
        findings = self.by_uid("calicocloud_many_vuln.json")
        self.assertEqual(["CVE-2000-0001"],
                         findings["calico-cloud-img-0001-CVE-2000-0001"].unsaved_vulnerability_ids)
        advisory = findings["calico-cloud-img-0001-CALICO-2024-0003"]
        self.assertIsNone(advisory.unsaved_vulnerability_ids)
        self.assertEqual("CALICO-2024-0003", advisory.vuln_id_from_tool)

    def test_a_title_repeating_the_id_is_not_doubled(self):
        finding = self.by_uid("calicocloud_many_vuln.json")["calico-cloud-img-0001-CVE-2000-0002"]
        self.assertEqual("CVE-2000-0002", finding.title)

    def test_a_vulnerability_with_neither_id_nor_name_still_has_a_title(self):
        finding = self.by_uid("calicocloud_many_vuln.json")["calico-cloud-img-0003-"]
        self.assertEqual("Calico Cloud image vulnerability", finding.title)
        self.assertIsNone(finding.vuln_id_from_tool)

    def test_the_package_name_key_wins_over_the_package_key(self):
        findings = self.parse_string(self.row(package="example-outer", package_name="example-inner"))
        self.assertEqual("example-inner", findings[0].component_name)

    def test_the_package_key_is_used_when_there_is_no_package_name(self):
        finding = self.by_uid("calicocloud_many_vuln.json")["calico-cloud-img-0001-CVE-2000-0002"]
        self.assertEqual("example-tls", finding.component_name)

    def test_a_single_fix_string_is_accepted_as_well_as_a_list(self):
        finding = self.by_uid("calicocloud_many_vuln.json")["calico-cloud-img-0001-CVE-2000-0002"]
        self.assertEqual("Upgrade example-tls to 3.0.2.", finding.mitigation)
        self.assertIn("**Fixed in:** 3.0.2", finding.description)

    def test_no_fix_means_no_mitigation(self):
        finding = self.by_uid("calicocloud_many_vuln.json")["calico-cloud-img-0001-CALICO-2024-0003"]
        self.assertIsNone(finding.mitigation)
        self.assertNotIn("**Fixed in:**", finding.description)

    def test_the_image_reference_falls_back_to_the_digest_then_the_id(self):
        findings = self.by_uid("calicocloud_many_vuln.json")
        digest_only = findings["calico-cloud-img-0003-"]
        self.assertIn("**Image:** sha256:3333", digest_only.description)
        id_only = findings["calico-cloud-img-0004-CVE-2000-0005"]
        self.assertIn("**Image:** img-0004", id_only.description)

    def test_a_trailing_slash_on_the_registry_is_not_doubled(self):
        """The fixture's registry ends in "/" and the reference must not carry "//"."""
        finding = self.by_uid("calicocloud_many_vuln.json")["calico-cloud-img-0001-CVE-2000-0001"]
        self.assertIn("**Image:** registry.example.com/generic-app:1.4.0", finding.description)
        self.assertNotIn("//generic-app", finding.description)

    def test_the_registry_is_only_prefixed_when_there_is_a_repository(self):
        payload = self.row()
        payload["images"][0]["registry"] = "registry.example.com"
        payload["images"][0]["repository"] = ""
        payload["images"][0]["digest"] = "sha256:abc"
        findings = self.parse_string(payload)
        self.assertIn("**Image:** sha256:abc", findings[0].description)

    def test_vulnerabilities_may_be_keyed_by_image_id_instead_of_nested(self):
        """
        Calico serves an image's vulnerabilities from a per-image endpoint.

        A saved export of both calls can nest them or key them by image id, so both work.
        """
        findings = self.by_uid("calicocloud_keyed_vulnerabilities.json")
        self.assertEqual(2, len(findings))
        self.assertIn("calico-cloud-img-0001-CVE-2000-0001", findings)
        self.assertIn("calico-cloud-img-0002-CVE-2000-0006", findings)
        self.assertIn("**Image:** registry.example.com/generic-worker:2.0.0",
                      findings["calico-cloud-img-0002-CVE-2000-0006"].description)

    def test_export_shapes(self):
        image = {"imageID": "img-1", "repository": "generic-app", "scan_result": "Fail",
                 "result": "Fail",
                 "vulnerabilities": [{"id": "CVE-2000-0001", "name": "A finding",
                                      "severity": "high", "package_name": "example-lib"}]}
        for payload in ([image], {"images": [image]}, {"data": [image]}, {"results": [image]}):
            with self.subTest(shape=str(payload)[:20]):
                self.assertEqual(1, len(self.parse_string(payload)))

    def test_a_bare_vulnerability_list_is_accepted_with_no_image_context(self):
        """
        A file holding only the vulnerability call still imports.

        The identity then carries an empty image id, which is exactly what the connector would build
        for an image it knows nothing about - the finding is not silently dropped.
        """
        vulns = [{"id": "CVE-2000-0001", "name": "A finding", "severity": "high",
                  "package_name": "example-lib", "version": "1.0.0", "cvss3Score": 7.5}]
        for payload in (vulns, {"vulnerabilities": vulns}):
            with self.subTest(shape=type(payload).__name__):
                findings = self.parse_string(payload)
                self.assertEqual(1, len(findings))
                self.assertEqual("calico-cloud--CVE-2000-0001", findings[0].unique_id_from_tool)
                self.assertNotIn("**Image:**", findings[0].description)

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("Calico Cloud", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("images", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        payload = {"images": ["not an object", None,
                              {"imageID": "img-9", "repository": "generic-app",
                               "scan_result": "Fail", "result": "Fail",
                               "vulnerabilities": ["not an object", None,
                                                   {"id": "CVE-2000-0007", "name": "A finding",
                                                    "severity": "low",
                                                    "package_name": "example-lib"}]}]}
        findings = self.parse_string(payload)
        self.assertEqual(1, len(findings))
        self.assertEqual("calico-cloud-img-9-CVE-2000-0007", findings[0].unique_id_from_tool)

    def test_an_image_with_no_vulnerabilities_contributes_nothing(self):
        self.assertEqual(0, len(self.parse_string({"images": [
            {"imageID": "img-1", "repository": "generic-app", "scan_result": "Pass",
             "result": "Pass"},
        ]})))

    def test_the_identity_spans_the_image_and_the_vulnerability(self):
        """
        The same CVE in two images is two findings - two things to fix.

        The hash spans the component and its version, so the identity is what separates them.
        """
        self.assertEqual(["title", "severity", "component_name", "component_version"],
                         CalicocloudParser().get_dedupe_fields())
        image = {"repository": "generic-app", "scan_result": "Fail", "result": "Fail",
                 "vulnerabilities": [{"id": "CVE-2000-0001", "name": "A finding",
                                      "severity": "high", "package_name": "example-lib",
                                      "version": "1.0.0"}]}
        findings = self.parse_string({"images": [
            {**image, "imageID": "img-a"},
            {**image, "imageID": "img-b"},
        ]})
        self.assertEqual(["calico-cloud-img-a-CVE-2000-0001", "calico-cloud-img-b-CVE-2000-0001"],
                         [finding.unique_id_from_tool for finding in findings])

    def test_the_date_is_the_result_time_then_when_it_was_scanned(self):
        findings = self.by_uid("calicocloud_many_vuln.json")
        self.assertEqual(date(2024, 6, 2), findings["calico-cloud-img-0001-CVE-2000-0001"].date)
        self.assertEqual(date(2024, 6, 4), findings["calico-cloud-img-0003-"].date)

    def test_an_image_with_no_timestamp_leaves_the_date_alone(self):
        finding = self.by_uid("calicocloud_many_vuln.json")["calico-cloud-img-0004-CVE-2000-0005"]
        self.assertEqual(date.today(), finding.date)

    def test_severity_is_always_a_known_value(self):
        for filename in ("calicocloud_many_vuln.json", "calicocloud_one_vuln.json",
                         "calicocloud_keyed_vulnerabilities.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
