import io
import json

from dojo.models import Finding, Test
from dojo.tools.dragos.parser import DragosParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDragosParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("dragos") / filename
        with path.open(encoding="utf-8") as file:
            return list(DragosParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(DragosParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def row(self, host=None, **overrides):
        vuln = {"id": "vuln-1", "title": "A finding", "severity": 3, "score": {"base": 5.0},
                "intel": {}}
        vuln.update(overrides)
        return {"content": [{"host": host or {"id": "asset-1", "name": "generic-plc-01"},
                             "vulnerability": vuln}]}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Dragos connector's ScanTypeName verbatim.

        Note it does NOT follow the "<Vendor> - Connectors Import" pattern the other connector scan
        types use, so it cannot be derived - it has to be copied.
        """
        parser = DragosParser()
        self.assertEqual(["Dragos Scan"], parser.get_scan_types())
        self.assertEqual("Dragos Scan", parser.get_label_for_scan_types("Dragos Scan"))
        self.assertNotIn("Dragos - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("dragos_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("dragos_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's finding_converter."""
        findings = self.parse("dragos_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Unauthenticated command execution on the controller", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("dragos-vuln-0001-asset-0001", finding.unique_id_from_tool)
        self.assertEqual("DRA-2024-0001", finding.vuln_id_from_tool)
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertEqual("generic-plc-01", finding.component_name)
        self.assertEqual("2.4.1", finding.component_version)
        self.assertTrue(finding.active)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(
            ["Generic Controls", "GC-9000", "Cell Zone A", "PLC", "ot-asset", "active-exploit"],
            finding.unsaved_tags,
        )
        self.assertEqual(
            "Restrict the control protocol to the engineering workstation segment.\n"
            "Apply vendor firmware 2.4.3 at the next maintenance window.",
            finding.mitigation,
        )
        self.assertEqual(
            "Dragos OT context: actively exploited; public proof of concept exists; "
            "remotely exploitable; Dragos risk score 8.5.",
            finding.severity_justification,
        )
        self.assertEqual(
            "**Summary:** The controller accepts control commands without authentication.\n"
            "**Description:** A device on the same network segment can issue control commands.\n"
            "**Dragos advisory:** DRA-2024-0001\n"
            "**Asset:** generic-plc-01\n"
            "**Vendor:** Generic Controls\n"
            "**Model:** GC-9000\n"
            "**Firmware:** 2.4.1\n"
            "**Zone:** Cell Zone A\n"
            "**Purdue level:** 1\n"
            "**IP:** 10.10.0.11, 10.10.0.12",
            finding.description,
        )

    def test_many_vuln(self):
        self.assertEqual(4, len(self.parse("dragos_many_vuln.json")))

    def test_the_cvss_score_decides_the_severity_not_dragos_own_scale(self):
        """
        The fixture's first finding is scored 9.8 but carries Dragos severity 2.

        Dragos's own scale runs the other way from a score - 5 is the most severe - so reading one as
        the other would inverte the whole ladder. CVSS is the portable signal, so it wins.
        """
        finding = self.by_uid("dragos_many_vuln.json")["dragos-vuln-0001-asset-0001"]
        self.assertEqual("Critical", finding.severity)
        self.assertEqual(9.8, finding.cvssv3_score)

    def test_the_dragos_scale_is_used_only_when_there_is_no_cvss_score(self):
        """Severity "4" on the 0-5 scale is High - and it arrives quoted, with a quoted "0" score."""
        finding = self.by_uid("dragos_many_vuln.json")["dragos-vuln-0002-asset-0002"]
        self.assertEqual("High", finding.severity)
        self.assertEqual(0.0, finding.cvssv3_score)

    def test_dragos_severity_levels(self):
        """5 is the most severe on Dragos's own scale, which is the inverse of a score."""
        for level, expected in ((5, "Critical"), (5.5, "Critical"), (4, "High"), (3, "Medium"),
                                (2, "Low"), (1, "Info"), (0, "Info"), ("", "Info")):
            with self.subTest(level=level):
                findings = self.parse_string(self.row(severity=level, score={"base": 0}))
                self.assertEqual(expected, findings[0].severity)

    def test_cvss_score_bands(self):
        cases = ((9.0, "Critical"), (9.8, "Critical"), (7.0, "High"), (8.9, "High"),
                 (4.0, "Medium"), (6.9, "Medium"), (0.1, "Low"), (3.9, "Low"))
        for score, expected in cases:
            with self.subTest(score=score):
                findings = self.parse_string(self.row(severity=0, score={"base": score}))
                self.assertEqual(expected, findings[0].severity)

    def test_purdue_level_zero_is_a_real_level_and_an_absent_one_is_not_reported(self):
        """
        Level 0 is the physical process layer - a real level, and the most sensitive one.

        Dragos leaves the field out when it does not know the level, so an absent level and level 0
        must not render alike.
        """
        findings = self.by_uid("dragos_many_vuln.json")
        self.assertIn("**Purdue level:** 0", findings["dragos-vuln-0002-asset-0002"].description)
        self.assertNotIn("**Purdue level:**", findings["dragos-vuln-0003-asset-0003"].description)

    def test_the_asset_falls_back_to_hostname_then_address_then_id(self):
        findings = self.by_uid("dragos_many_vuln.json")
        self.assertEqual("generic-hmi-02.plant.example.com",
                         findings["dragos-vuln-0002-asset-0002"].component_name)
        # A blank hostname is skipped, so the address is used.
        self.assertEqual("10.10.0.31", findings["dragos-vuln-0003-asset-0003"].component_name)
        self.assertEqual("asset-0004", findings["dragos-vuln-0004-asset-0004"].component_name)

    def test_the_hardware_vendor_is_the_fallback_for_the_asset_vendor(self):
        findings = self.by_uid("dragos_many_vuln.json")
        self.assertIn("**Vendor:** Generic HMI Works",
                      findings["dragos-vuln-0002-asset-0002"].description)
        self.assertIn("Generic HMI Works", findings["dragos-vuln-0002-asset-0002"].unsaved_tags)

    def test_the_title_falls_back_to_the_advisory_then_the_internal_id(self):
        findings = self.parse_string(self.row(title="", report_id="DRA-2024-0009"))
        self.assertEqual("DRA-2024-0009", findings[0].title)
        findings = self.parse_string(self.row(title="", report_id=""))
        self.assertEqual("Dragos vulnerability vuln-1", findings[0].title)

    def test_the_vuln_id_prefers_the_dragos_advisory(self):
        """The advisory is what an OT engineer looks up; the internal id is the last resort."""
        findings = self.by_uid("dragos_many_vuln.json")
        self.assertEqual("DRA-2024-0001", findings["dragos-vuln-0001-asset-0001"].vuln_id_from_tool)
        # No advisory and no enumeration, so the reference is used.
        self.assertEqual("GHSA-aaaa-bbbb-cccc",
                         findings["dragos-vuln-0003-asset-0003"].vuln_id_from_tool)
        self.assertEqual("vuln-0004", findings["dragos-vuln-0004-asset-0004"].vuln_id_from_tool)

    def test_advisory_ids_are_sorted_not_kept_in_the_order_they_appear(self):
        """
        The connector's shared extractor SORTS its results, unlike the order-preserving call.

        The fixture's reference names CVE-2000-0002 before CVE-2000-0001, and the enumeration repeats
        the second - so the result is both sorted and deduplicated.
        """
        finding = self.by_uid("dragos_many_vuln.json")["dragos-vuln-0001-asset-0001"]
        self.assertEqual(["CVE-2000-0001", "CVE-2000-0002"], finding.unsaved_vulnerability_ids)

    def test_identifiers_are_read_from_the_reference_enumeration_and_title(self):
        for field in ("reference", "enumeration", "title"):
            with self.subTest(field=field):
                findings = self.parse_string(self.row(**{field: "see CVE-2000-0005 for details"}))
                self.assertEqual(["CVE-2000-0005"], findings[0].unsaved_vulnerability_ids)

    def test_non_cve_advisory_formats_are_recognised(self):
        for identifier in ("GHSA-aaaa-bbbb-cccc", "GO-2024-1234", "RHSA-2024:1234"):
            with self.subTest(identifier=identifier):
                findings = self.parse_string(self.row(reference=identifier))
                self.assertEqual([identifier], findings[0].unsaved_vulnerability_ids)

    def test_a_finding_with_no_identifier_has_none(self):
        findings = self.by_uid("dragos_many_vuln.json")
        self.assertIsNone(findings["dragos-vuln-0004-asset-0004"].unsaved_vulnerability_ids)

    def test_the_ot_context_is_a_justification_not_a_regrade(self):
        """
        Exploitability decides whether a flaw waits for the next outage or the next window.

        It is recorded as the justification: moving the severity would make the same CVE a different
        severity here than in an API sync.
        """
        findings = self.by_uid("dragos_many_vuln.json")
        exploited = findings["dragos-vuln-0001-asset-0001"]
        self.assertEqual(
            "Dragos OT context: actively exploited; remotely exploitable; Dragos risk score 8.5.",
            exploited.severity_justification,
        )
        self.assertEqual("Critical", exploited.severity)

        poc_only = findings["dragos-vuln-0002-asset-0002"]
        self.assertEqual("Dragos OT context: public proof of concept exists; Dragos risk score 6.",
                         poc_only.severity_justification)

    def test_no_ot_context_leaves_the_justification_unset(self):
        findings = self.by_uid("dragos_many_vuln.json")
        self.assertIsNone(findings["dragos-vuln-0003-asset-0003"].severity_justification)

    def test_the_risk_score_renders_without_a_trailing_zero(self):
        """The connector formats it in its shortest round-tripping form, so 6.0 is "6"."""
        for score, expected in ((8.5, "8.5"), (6, "6"), (6.0, "6"), (7.25, "7.25")):
            with self.subTest(score=score):
                findings = self.parse_string(self.row(dragos_score=score,
                                                      intel={"active_exploit": False}))
                self.assertEqual(f"Dragos OT context: Dragos risk score {expected}.",
                                 findings[0].severity_justification)

    def test_active_exploit_is_tagged_but_the_other_flags_are_not(self):
        findings = self.by_uid("dragos_many_vuln.json")
        self.assertIn("active-exploit", findings["dragos-vuln-0001-asset-0001"].unsaved_tags)
        self.assertNotIn("active-exploit", findings["dragos-vuln-0002-asset-0002"].unsaved_tags)

    def test_only_an_ot_asset_is_tagged_as_one(self):
        findings = self.by_uid("dragos_many_vuln.json")
        self.assertIn("ot-asset", findings["dragos-vuln-0001-asset-0001"].unsaved_tags)
        self.assertNotIn("ot-asset", findings["dragos-vuln-0003-asset-0003"].unsaved_tags)

    def test_an_empty_mitigation_list_leaves_the_mitigation_unset(self):
        findings = self.by_uid("dragos_many_vuln.json")
        self.assertIsNone(findings["dragos-vuln-0002-asset-0002"].mitigation)
        self.assertEqual("Segment the control network.",
                         findings["dragos-vuln-0001-asset-0001"].mitigation)

    def test_export_shapes(self):
        detection = {"host": {"id": "asset-1", "name": "generic-plc-01"},
                     "vulnerability": {"id": "vuln-1", "title": "A finding", "severity": 3,
                                       "score": {"base": 5.0}}}
        for payload in ([detection], {"content": [detection]}, {"detections": [detection]},
                        {"data": [detection]}, {"results": [detection]}):
            with self.subTest(shape=str(payload)[:20]):
                self.assertEqual(1, len(self.parse_string(payload)))

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("Dragos", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("content", str(context.exception))

    def test_a_detection_missing_its_blocks_is_still_a_finding(self):
        """
        A detection with no host or no vulnerability block is degenerate but not malformed.

        The connector reads both as values rather than pointers, so an absent block is an empty one
        and the finding is still produced.
        """
        findings = self.parse_string({"content": [{}]})
        self.assertEqual(1, len(findings))
        self.assertEqual("dragos--", findings[0].unique_id_from_tool)
        self.assertEqual("Dragos vulnerability ", findings[0].title)
        self.assertEqual("Info", findings[0].severity)

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"content": [
            "not an object",
            None,
            {"host": {"id": "asset-9"}, "vulnerability": {"id": "vuln-9", "title": "A finding",
                                                          "severity": 3}},
        ]})
        self.assertEqual(1, len(findings))
        self.assertEqual("dragos-vuln-9-asset-9", findings[0].unique_id_from_tool)

    def test_the_identity_spans_the_flaw_and_the_asset(self):
        """
        The same advisory on two devices is two findings - two devices to patch.

        In an OT estate those two may sit at different Purdue levels, which is exactly why they must
        not collapse into one.
        """
        self.assertEqual(["title", "severity", "component_name"], DragosParser().get_dedupe_fields())
        vuln = {"id": "vuln-1", "title": "A finding", "severity": 4, "score": {"base": 7.5}}
        findings = self.parse_string({"content": [
            {"host": {"id": "asset-a", "name": "generic-plc-a"}, "vulnerability": vuln},
            {"host": {"id": "asset-b", "name": "generic-plc-b"}, "vulnerability": vuln},
        ]})
        self.assertEqual(["dragos-vuln-1-asset-a", "dragos-vuln-1-asset-b"],
                         [finding.unique_id_from_tool for finding in findings])
        self.assertEqual(["generic-plc-a", "generic-plc-b"],
                         [finding.component_name for finding in findings])

    def test_severity_is_always_a_known_value(self):
        for filename in ("dragos_many_vuln.json", "dragos_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
