import io
import json
from datetime import UTC, datetime

from dojo.models import Finding, Test
from dojo.tools.defender_for_cloud.parser import DefenderForCloudParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDefenderForCloudParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("defender_for_cloud") / filename
        with path.open(encoding="utf-8") as file:
            return list(DefenderForCloudParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(DefenderForCloudParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def row(self, properties, identifier="sub-1"):
        return {"value": [{"id": identifier, "properties": properties}]}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Defender for Cloud connector's ScanTypeName verbatim.

        Note this is a different product from Microsoft Defender for Endpoint, which DefectDojo already
        parses as `ms_defender` - a separate scan type, a separate parser, and not to be conflated.
        """
        parser = DefenderForCloudParser()
        self.assertEqual(["Microsoft Defender for Cloud - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "Microsoft Defender for Cloud - Connectors Import",
            parser.get_label_for_scan_types("Microsoft Defender for Cloud - Connectors Import"),
        )

    def test_the_dedupe_hash_is_the_arm_id_alone(self):
        """
        The ARM sub-assessment id already encodes the subscription, the resource and the finding.

        It is therefore the whole identity, and adding a volatile field would split a finding that had
        merely been regraded.
        """
        self.assertEqual(["unique_id_from_tool"], DefenderForCloudParser().get_dedupe_fields())

    def test_no_vuln(self):
        """
        Posture recommendations and healthy findings are not vulnerabilities.

        Healthy ones are left out so a reimport closes them rather than resurrecting them.
        """
        self.assertEqual(0, len(self.parse("defender_for_cloud_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("defender_for_cloud_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's finding_converter."""
        findings = self.parse("defender_for_cloud_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("CVE-2000-0001 in openssl", finding.title)
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual(
            "Defender for Cloud assigned severity **High**. CVSS v3 base score 9.8.",
            finding.severity_justification,
        )
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertEqual("openssl", finding.component_name)
        self.assertEqual("3.0.2", finding.component_version)
        self.assertEqual("CVE-2000-0001", finding.vuln_id_from_tool)
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual(datetime(2024, 7, 1, tzinfo=UTC).date(), finding.date)
        self.assertEqual(
            "An attacker who reaches the service can run code as the service account.",
            finding.impact,
        )
        self.assertFalse(finding.static_finding)
        self.assertTrue(finding.dynamic_finding)
        self.assertIn("sub-0001", finding.unique_id_from_tool)

        self.assertEqual(
            "**Assessed resource:** web-node-1\n"
            "**Package:** openssl 3.0.2\n"
            "**Fixed version:** 3.0.13\n"
            "\nA memory-safety flaw allows remote code execution.",
            finding.description,
        )
        self.assertEqual(
            "Update openssl to 3.0.13 or later.\n\nApply the vendor update through your patching process.",
            finding.mitigation,
        )
        self.assertEqual(
            "https://nvd.example.com/vuln/detail/CVE-2000-0001\nhttps://vendor.example.com/advisory/1",
            finding.references,
        )

    def test_many_vuln(self):
        """Six sub-assessments; three are not open vulnerabilities."""
        self.assertEqual(3, len(self.parse("defender_for_cloud_many_vuln.json")))

    def test_only_unhealthy_sub_assessments_are_imported(self):
        for code, imported in (("Unhealthy", 1), ("Healthy", 0), ("NotApplicable", 0), ("", 0)):
            with self.subTest(code=code):
                findings = self.parse_string(self.row({
                    "displayName": "CVE-2000-0001", "status": {"code": code, "severity": "High"},
                    "additionalData": {"assessedResourceType": "ServerVulnerabilityTvm"},
                }))
                self.assertEqual(imported, len(findings))

    def test_posture_sub_assessments_are_not_vulnerabilities(self):
        """SQL baselines and posture checks carry no CVEs, so they are excluded by resource type."""
        for resource_type in ("SqlServerVulnerability", "GeneralVulnerability"):
            with self.subTest(resource_type=resource_type):
                findings = self.parse_string(self.row({
                    "displayName": "A recommendation", "status": {"code": "Unhealthy", "severity": "High"},
                    "additionalData": {"assessedResourceType": resource_type},
                }))
                self.assertEqual(0, len(findings))

    def test_an_unfamiliar_resource_type_is_decided_by_whether_it_has_a_cve(self):
        """
        A new Defender scanner should not be dropped silently, and a configuration baseline should not
        arrive as a vulnerability. The presence of a CVE is what tells them apart.
        """
        findings = self.by_uid("defender_for_cloud_many_vuln.json")
        self.assertIn("sub-0005", findings)
        self.assertNotIn("sub-0006", findings)

    def test_the_tvm_cve_field_may_be_a_list_an_object_or_a_string(self):
        """The connector's decoder accepts all three, so a file carrying any of them reads the same."""
        for cve in ("CVE-2000-0005",
                    {"title": "CVE-2000-0005"},
                    [{"title": "CVE-2000-0005"}],
                    ["CVE-2000-0005"]):
            with self.subTest(shape=type(cve).__name__):
                findings = self.parse_string(self.row({
                    "displayName": "A finding", "status": {"code": "Unhealthy", "severity": "High"},
                    "additionalData": {"assessedResourceType": "SomeFutureType", "cve": cve},
                }))
                self.assertEqual(1, len(findings))
                self.assertEqual(["CVE-2000-0005"], findings[0].unsaved_vulnerability_ids)

    def test_severity_labels(self):
        for label, expected in (("Critical", "Critical"), ("High", "High"), ("medium", "Medium"),
                                ("Low", "Low"), ("not a label", "Info"), ("", "Info")):
            with self.subTest(label=label):
                findings = self.parse_string(self.row({
                    "displayName": "CVE-2000-0001", "status": {"code": "Unhealthy", "severity": label},
                    "additionalData": {"assessedResourceType": "ServerVulnerabilityTvm"},
                }))
                self.assertEqual(expected, findings[0].severity)

    def test_the_raw_label_is_kept_as_the_justification(self):
        finding = self.by_uid("defender_for_cloud_many_vuln.json")["sub-0005"]
        self.assertEqual("Info", finding.severity)
        self.assertEqual(
            "Defender for Cloud assigned severity **not a label**.",
            finding.severity_justification,
        )

    def test_the_package_is_read_from_either_finding_shape(self):
        """
        A container finding puts the package under softwareDetails; a server finding flattens it.

        Reading only one shape would leave every finding of the other kind with no component - and the
        component is what a reviewer patches.
        """
        findings = self.by_uid("defender_for_cloud_many_vuln.json")
        server = findings[[uid for uid in findings if "sub-0001" in uid][0]]
        self.assertEqual("openssl", server.component_name)
        self.assertEqual("3.0.2", server.component_version)

        container = findings[[uid for uid in findings if "sub-0002" in uid][0]]
        self.assertEqual("libxml2", container.component_name)
        self.assertEqual("2.9.13", container.component_version)

    def test_a_container_finding_names_the_image_and_digest(self):
        findings = self.by_uid("defender_for_cloud_many_vuln.json")
        container = findings[[uid for uid in findings if "sub-0002" in uid][0]]
        self.assertIn("**Image:** exampleacr.azurecr.example.com/generic-app", container.description)
        self.assertIn("**Digest:** sha256:", container.description)

    def test_a_server_finding_has_no_image_lines(self):
        findings = self.by_uid("defender_for_cloud_many_vuln.json")
        server = findings[[uid for uid in findings if "sub-0001" in uid][0]]
        self.assertNotIn("**Image:**", server.description)
        self.assertNotIn("**Digest:**", server.description)

    def test_the_highest_cvss_wins_and_only_v3_reaches_the_v3_field(self):
        """
        Defender reports a flat v3.0 score on some shapes and a version-keyed map on others.

        The highest wins, and a v2 base must not land in a v3 field - the same number means different
        things on the two scales. The justification still records which version it was.
        """
        findings = self.by_uid("defender_for_cloud_many_vuln.json")
        server = findings[[uid for uid in findings if "sub-0001" in uid][0]]
        self.assertEqual(9.8, server.cvssv3_score)

        container = findings[[uid for uid in findings if "sub-0002" in uid][0]]
        self.assertIsNone(container.cvssv3_score)
        self.assertIn("CVSS v2 base score 5.0.", container.severity_justification)

    def test_the_title_only_appends_the_package_for_a_bare_cve(self):
        """
        "CVE-2000-0001" alone says nothing about what is affected, and one CVE usually appears against
        several packages on the same host. A descriptive name is left as it is.
        """
        findings = self.by_uid("defender_for_cloud_many_vuln.json")
        self.assertEqual("A future scanner's finding", findings["sub-0005"].title)

        named = self.parse_string(self.row({
            "displayName": "Vulnerable OpenSSL detected", "status": {"code": "Unhealthy", "severity": "High"},
            "additionalData": {"assessedResourceType": "ServerVulnerabilityTvm", "softwareName": "openssl"},
        }))
        self.assertEqual("Vulnerable OpenSSL detected", named[0].title)

    def test_the_resource_label_falls_back_to_the_last_segment_of_an_arm_id(self):
        """
        An ARM id is a path, and its last segment is the resource.

        Printing the whole path would bury the one part a reader needs.
        """
        findings = self.by_uid("defender_for_cloud_many_vuln.json")
        container = findings[[uid for uid in findings if "sub-0002" in uid][0]]
        self.assertIn("**Assessed resource:** exampleacr", container.description)

    def test_cve_ids_are_matched_anchored_not_as_substrings(self):
        """
        A reference title is either a CVE id or it is prose.

        A substring match would pull an id out of a sentence like "supersedes CVE-2000-0009", which is
        a different finding's identifier.
        """
        findings = self.parse_string(self.row({
            "displayName": "CVE-2000-0001", "status": {"code": "Unhealthy", "severity": "High"},
            "additionalData": {
                "assessedResourceType": "ServerVulnerabilityTvm",
                "vulnerabilityDetails": {
                    "cveId": "CVE-2000-0001",
                    "references": [{"title": "supersedes CVE-2000-0009", "link": "https://example.com/a"}],
                },
            },
        }))
        self.assertEqual(["CVE-2000-0001"], findings[0].unsaved_vulnerability_ids)

    def test_mitigation_keeps_both_the_version_and_defenders_text(self):
        """They answer different questions - what to do and how - and neither is always present."""
        findings = self.by_uid("defender_for_cloud_many_vuln.json")
        container = findings[[uid for uid in findings if "sub-0002" in uid][0]]
        self.assertEqual("Update libxml2 to 2.9.14 or later.", container.mitigation)

        only_text = self.parse_string(self.row({
            "displayName": "CVE-2000-0001", "remediation": "Follow the vendor advisory.",
            "status": {"code": "Unhealthy", "severity": "High"},
            "additionalData": {"assessedResourceType": "ServerVulnerabilityTvm"},
        }))
        self.assertEqual("Follow the vendor advisory.", only_text[0].mitigation)

    def test_export_shapes(self):
        properties = {"displayName": "CVE-2000-0001", "status": {"code": "Unhealthy", "severity": "High"},
                      "additionalData": {"assessedResourceType": "ServerVulnerabilityTvm"}}
        row = {"id": "sub-1", "properties": properties}
        for payload in ({"value": [row]}, [row], row):
            with self.subTest(shape=type(payload).__name__):
                self.assertEqual(1, len(self.parse_string(payload)))

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("Defender for Cloud", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("value", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"value": [
            "not an object",
            None,
            {"id": "no-properties"},
            {"id": "sub-1", "properties": {"displayName": "CVE-2000-0001",
                                          "status": {"code": "Unhealthy", "severity": "High"},
                                          "additionalData": {"assessedResourceType": "ServerVulnerabilityTvm"}}},
        ]})
        self.assertEqual(1, len(findings))

    def test_severity_is_always_a_known_value(self):
        for filename in ("defender_for_cloud_many_vuln.json", "defender_for_cloud_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
