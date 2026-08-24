import io
import json

from dojo.models import Finding, Test
from dojo.tools.netrise.parser import NetriseParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestNetriseParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("netrise") / filename
        with path.open(encoding="utf-8") as file:
            return list(NetriseParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(NetriseParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def row(self, **overrides):
        node = {"cve": "CVE-2000-0001", "name": "example-lib", "severity": "high", "cvssScore": 7.5}
        node.update(overrides)
        return {"asset": {"id": "artifact-1", "name": "generic-firmware.bin"},
                "vulnerabilities": {"edges": [{"node": node}]}}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the NetRise connector's ScanTypeName verbatim.

        Note it does NOT follow the "<Vendor> - Connectors Import" pattern the other connector scan
        types use, so it cannot be derived - it has to be copied.
        """
        parser = NetriseParser()
        self.assertEqual(["NetRise Scan"], parser.get_scan_types())
        self.assertEqual("NetRise Scan", parser.get_label_for_scan_types("NetRise Scan"))
        self.assertNotIn("NetRise - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("netrise_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("netrise_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's finding_converter."""
        findings = self.parse("netrise_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("CVE-2000-0001 in example-tls", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("netrise-artifact-0001-CVE-2000-0001", finding.unique_id_from_tool)
        self.assertEqual("CVE-2000-0001", finding.vuln_id_from_tool)
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual("example-tls", finding.component_name)
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertEqual("Upgrade to a fixed version: 1.1.1w, 3.0.12.", finding.mitigation)
        self.assertTrue(finding.active)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(["Generic Networks", "GN-1000", "reachable", "cisa-kev"],
                         finding.unsaved_tags)
        self.assertEqual(
            "NetRise marks this vulnerability as reachable in the firmware. "
            "Listed in CISA's Known Exploited Vulnerabilities catalog.",
            finding.severity_justification,
        )
        self.assertEqual(
            "**Component:** example-tls\n"
            "**Artifact:** generic-router-firmware-1.4.0.bin\n"
            "**Vendor:** Generic Networks\n"
            "**Product:** GN-1000\n"
            "**Firmware version:** 1.4.0\n"
            "**Reachable:** yes\n"
            "**CISA KEV:** yes",
            finding.description,
        )

    def test_many_vuln(self):
        self.assertEqual(5, len(self.parse("netrise_many_vuln.json")))

    def test_an_unrecognised_severity_word_falls_through_to_the_score(self):
        """
        Falling back to Info would bury a finding NetRise graded with a word this does not know.

        The score is the safer fallback: 7.5 is High whatever the word says.
        """
        finding = self.by_uid("netrise_many_vuln.json")["netrise-artifact-0001-CVE-2000-0002"]
        self.assertEqual("High", finding.severity)
        self.assertEqual(7.5, finding.cvssv3_score)

    def test_severity_words(self):
        for label, expected in (("critical", "Critical"), ("high", "High"), ("medium", "Medium"),
                                ("low", "Low"), ("info", "Info"), ("informational", "Info"),
                                ("none", "Info"), ("CRITICAL", "Critical")):
            with self.subTest(label=label):
                # A high score would win if the word were not recognised, so it proves the word did.
                findings = self.parse_string(self.row(severity=label, cvssScore=9.9))
                self.assertEqual(expected, findings[0].severity)

    def test_cvss_score_bands(self):
        for score, expected in ((9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low"),
                                (0, "Info")):
            with self.subTest(score=score):
                findings = self.parse_string(self.row(severity="", cvssScore=score))
                self.assertEqual(expected, findings[0].severity)

    def test_a_quoted_score_is_accepted(self):
        finding = self.by_uid("netrise_many_vuln.json")["netrise-artifact-0001-CVE-2000-0002"]
        self.assertEqual(7.5, finding.cvssv3_score)

    def test_the_identity_is_scoped_to_the_firmware_artifact(self):
        """
        The same CVE in two firmware builds is two findings - two builds to re-release.

        Merging them would hide that one of the two is still shipping.
        """
        node = {"cve": "CVE-2000-0001", "name": "example-lib", "severity": "high"}
        first = self.parse_string({"asset": {"id": "artifact-a"},
                                   "vulnerabilities": {"edges": [{"node": node}]}})
        second = self.parse_string({"asset": {"id": "artifact-b"},
                                    "vulnerabilities": {"edges": [{"node": node}]}})
        self.assertEqual("netrise-artifact-a-CVE-2000-0001", first[0].unique_id_from_tool)
        self.assertEqual("netrise-artifact-b-CVE-2000-0001", second[0].unique_id_from_tool)

    def test_the_identity_falls_back_to_the_component_when_there_is_no_cve(self):
        finding = self.by_uid("netrise_many_vuln.json")[
            "netrise-artifact-0001-example-config-weakness"]
        self.assertEqual("example-config-weakness", finding.title)
        self.assertIsNone(finding.vuln_id_from_tool)
        self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_the_title_falls_back_through_the_cve_and_the_component(self):
        findings = self.by_uid("netrise_many_vuln.json")
        self.assertEqual("CVE-2000-0004", findings["netrise-artifact-0001-CVE-2000-0004"].title)
        self.assertEqual("NetRise vulnerability", findings["netrise-artifact-0001-"].title)

    def test_reachability_and_kev_are_justifications_not_regrades(self):
        """
        A reachable, actively-exploited flaw in firmware is more urgent than its score says.

        It is recorded as the justification so a reviewer sees why - changing the grade would make it
        disagree with an API sync of the same finding.
        """
        findings = self.by_uid("netrise_many_vuln.json")
        reachable_only = findings["netrise-artifact-0001-example-config-weakness"]
        self.assertEqual("NetRise marks this vulnerability as reachable in the firmware.",
                         reachable_only.severity_justification)
        self.assertEqual("Info", reachable_only.severity)

        kev_only = findings["netrise-artifact-0001-CVE-2000-0004"]
        self.assertEqual("Listed in CISA's Known Exploited Vulnerabilities catalog.",
                         kev_only.severity_justification)

    def test_neither_marker_leaves_the_justification_unset(self):
        finding = self.by_uid("netrise_many_vuln.json")["netrise-artifact-0001-CVE-2000-0002"]
        self.assertIsNone(finding.severity_justification)
        self.assertEqual(["Generic Networks", "GN-1000"], finding.unsaved_tags)

    def test_the_markers_are_also_tags(self):
        findings = self.by_uid("netrise_many_vuln.json")
        self.assertIn("reachable", findings["netrise-artifact-0001-example-config-weakness"].unsaved_tags)
        self.assertIn("cisa-kev", findings["netrise-artifact-0001-CVE-2000-0004"].unsaved_tags)

    def test_no_fix_versions_leaves_the_mitigation_unset(self):
        findings = self.by_uid("netrise_many_vuln.json")
        self.assertIsNone(findings["netrise-artifact-0001-CVE-2000-0002"].mitigation)
        self.assertEqual("Upgrade to a fixed version: 1.1.1w, 3.0.12.",
                         findings["netrise-artifact-0001-CVE-2000-0001"].mitigation)

    def test_relay_edges_are_unwrapped_and_a_flat_list_is_accepted(self):
        """
        NetRise answers GraphQL Relay, so each row arrives wrapped in a "node".

        A file somebody has already flattened still imports - the row is used as-is when there is no
        node to unwrap.
        """
        node = {"cve": "CVE-2000-0001", "name": "example-lib", "severity": "high"}
        for vulnerabilities in ({"edges": [{"node": node}]}, [{"node": node}], [node]):
            with self.subTest(shape=str(vulnerabilities)[:20]):
                findings = self.parse_string({"asset": {"id": "artifact-1"},
                                              "vulnerabilities": vulnerabilities})
                self.assertEqual(1, len(findings))
                self.assertEqual("netrise-artifact-1-CVE-2000-0001",
                                 findings[0].unique_id_from_tool)

    def test_the_graphql_data_envelope_is_accepted(self):
        node = {"cve": "CVE-2000-0001", "name": "example-lib", "severity": "high"}
        findings = self.parse_string({"data": {"asset": {"id": "artifact-1"},
                                               "vulnerabilities": {"edges": [{"node": node}]}}})
        self.assertEqual(1, len(findings))
        self.assertEqual("netrise-artifact-1-CVE-2000-0001", findings[0].unique_id_from_tool)

    def test_the_artifact_may_come_from_the_assets_relay_query(self):
        """A saved export of both queries carries the artifact in its own Relay envelope."""
        node = {"cve": "CVE-2000-0001", "name": "example-lib", "severity": "high"}
        findings = self.parse_string({
            "assetsRelay": {"edges": [{"node": {"id": "artifact-7", "name": "generic-firmware.bin",
                                                "vendor": "Generic Networks"}}]},
            "vulnerabilities": {"edges": [{"node": node}]}})
        self.assertEqual("netrise-artifact-7-CVE-2000-0001", findings[0].unique_id_from_tool)
        self.assertIn("**Artifact:** generic-firmware.bin", findings[0].description)

    def test_a_row_may_carry_its_own_artifact(self):
        node = {"cve": "CVE-2000-0001", "name": "example-lib", "severity": "high",
                "asset": {"id": "artifact-own", "name": "own-firmware.bin"}}
        findings = self.parse_string({"asset": {"id": "artifact-file"},
                                      "vulnerabilities": {"edges": [{"node": node}]}})
        self.assertEqual("netrise-artifact-own-CVE-2000-0001", findings[0].unique_id_from_tool)

    def test_an_export_with_no_artifact_still_imports(self):
        """
        The connector always has an artifact; a file might not.

        The finding is still produced rather than dropped, with an empty artifact in the identity.
        """
        findings = self.parse_string({"vulnerabilities": {"edges": [
            {"node": {"cve": "CVE-2000-0001", "name": "example-lib", "severity": "high"}}]}})
        self.assertEqual(1, len(findings))
        self.assertEqual("netrise--CVE-2000-0001", findings[0].unique_id_from_tool)
        self.assertNotIn("**Artifact:**", findings[0].description)

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("NetRise", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("vulnerabilities", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"asset": {"id": "artifact-1"}, "vulnerabilities": {"edges": [
            "not an object",
            None,
            {"node": "not an object"},
            {"node": {"cve": "CVE-2000-0009", "name": "example-lib", "severity": "low"}},
        ]}})
        # A row whose node is not an object falls back to the row itself, which has no cve or name.
        self.assertEqual(2, len(findings))
        self.assertIn("netrise-artifact-1-CVE-2000-0009",
                      [finding.unique_id_from_tool for finding in findings])

    def test_the_component_is_in_the_hash(self):
        self.assertEqual(["title", "severity", "component_name"], NetriseParser().get_dedupe_fields())

    def test_severity_is_always_a_known_value(self):
        for filename in ("netrise_many_vuln.json", "netrise_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
