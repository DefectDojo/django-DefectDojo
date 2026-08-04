import io
import json

from dojo.models import Finding, Test
from dojo.tools.nozomi.parser import NozomiParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestNozomiParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("nozomi") / filename
        with path.open(encoding="utf-8") as file:
            return list(NozomiParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(NozomiParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def row(self, **overrides):
        row = {"id": "nc-1", "cve": "CVE-2000-0001", "cve_score": 7.5,
               "node_label": "generic-plc-01", "asset_id": "asset-1"}
        row.update(overrides)
        return {"result": [row]}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Nozomi connector's ScanTypeName verbatim.

        Note it does NOT follow the "<Vendor> - Connectors Import" pattern the other connector scan
        types use, so it cannot be derived - it has to be copied.
        """
        parser = NozomiParser()
        self.assertEqual(["Nozomi Vantage Scan"], parser.get_scan_types())
        self.assertEqual("Nozomi Vantage Scan", parser.get_label_for_scan_types("Nozomi Vantage Scan"))
        self.assertNotIn("Nozomi - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("nozomi_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("nozomi_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's finding_converter."""
        findings = self.parse("nozomi_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("CVE-2000-0001 on generic-plc-01", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("nozomi-nc-0001", finding.unique_id_from_tool)
        self.assertEqual("CVE-2000-0001", finding.vuln_id_from_tool)
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertEqual(787, finding.cwe)
        self.assertEqual("GC-9000", finding.component_name)
        self.assertEqual("2.4.1", finding.component_version)
        self.assertEqual("Apply hotfix 2.4.3.", finding.mitigation)
        self.assertEqual("https://example.com/advisories/CVE-2000-0001\n"
                         "https://example.com/vendor/advisory-2024-01", finding.references)
        self.assertTrue(finding.active)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(["Generic Controls", "PLC", "GC-9000", "Cell Zone A"], finding.unsaved_tags)
        self.assertEqual(
            "**Asset:** generic-plc-01\n"
            "**Type:** PLC\n"
            "**Vendor:** Generic Controls\n"
            "**Product:** GC-9000\n"
            "**Firmware:** 2.4.1\n"
            "**OS:** GCOS 4\n"
            "**Zone:** Cell Zone A\n"
            "**Weakness:** Out-of-bounds Write\n\n"
            "A crafted control message causes the controller to execute attacker code.",
            finding.description,
        )

    def test_many_vuln(self):
        """Five records, but the resolved one is never imported."""
        self.assertEqual(4, len(self.parse("nozomi_many_vuln.json")))

    def test_a_resolved_record_is_skipped(self):
        """
        The connector queries "node_cves | where resolved != true", so an API sync never sees these.

        A hand-run query can return them, and importing one would open a finding Nozomi has already
        closed - so the query filter is mirrored here, not only the converter.
        """
        findings = self.by_uid("nozomi_many_vuln.json")
        self.assertNotIn("nozomi-nc-0004", findings)
        for finding in findings.values():
            self.assertNotIn("Never imported", str(finding.description))

    def test_only_a_true_resolved_flag_skips_a_record(self):
        """An absent flag, or a false one, is an open vulnerability."""
        for resolved, expected in ((True, 0), (False, 1), (None, 1)):
            with self.subTest(resolved=resolved):
                row = {"id": "nc-1", "cve": "CVE-2000-0001", "cve_score": 7.5}
                if resolved is not None:
                    row["resolved"] = resolved
                self.assertEqual(expected, len(self.parse_string({"result": [row]})))

    def test_a_record_with_no_resolved_key_is_imported(self):
        finding = self.by_uid("nozomi_many_vuln.json")["nozomi-nc-0005"]
        self.assertEqual("Medium", finding.severity)

    def test_cvss_score_bands(self):
        """Nozomi sends no severity word, so the score is the only signal."""
        for score, expected in ((9.0, "Critical"), (9.8, "Critical"), (7.0, "High"), (4.0, "Medium"),
                                (0.1, "Low"), (0, "Info")):
            with self.subTest(score=score):
                findings = self.parse_string(self.row(cve_score=score))
                self.assertEqual(expected, findings[0].severity)

    def test_a_quoted_score_is_accepted(self):
        finding = self.by_uid("nozomi_many_vuln.json")["nozomi-CVE-2000-0002-asset-0002"]
        self.assertEqual(7.5, finding.cvssv3_score)
        self.assertEqual("High", finding.severity)

    def test_an_unscored_record_is_info_rather_than_dropped(self):
        """In an OT estate the asset context is worth recording even with no score."""
        finding = self.by_uid("nozomi_many_vuln.json")["nozomi-nc-0003"]
        self.assertEqual("Info", finding.severity)
        self.assertEqual(0.0, finding.cvssv3_score)

    def test_the_identity_falls_back_to_the_cve_and_the_asset(self):
        """Vantage's record id is preferred; without one the CVE plus the asset keeps rows apart."""
        findings = self.by_uid("nozomi_many_vuln.json")
        self.assertIn("nozomi-CVE-2000-0002-asset-0002", findings)
        self.assertIn("nozomi-nc-0001", findings)

    def test_the_title_has_no_asset_only_form(self):
        """
        A record with no CVE has nothing to name it by, so it falls through to a generic title.

        Titling it after the device would read as though the device itself were the finding.
        """
        finding = self.by_uid("nozomi_many_vuln.json")["nozomi-nc-0003"]
        self.assertEqual("Nozomi vulnerability", finding.title)
        self.assertIn("**Asset:** generic-rtu-03", finding.description)

    def test_a_record_with_no_cve_carries_no_vulnerability_id(self):
        finding = self.by_uid("nozomi_many_vuln.json")["nozomi-nc-0003"]
        self.assertIsNone(finding.vuln_id_from_tool)
        self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_cwe_forms(self):
        for value, expected in (("CWE-787", 787), ("787", 787), ("cwe-787", 787),
                                ("not a cwe", 0), ("", 0)):
            with self.subTest(value=value):
                findings = self.parse_string(self.row(cwe_id=value))
                self.assertEqual(expected, findings[0].cwe)

    def test_a_bare_cwe_number_is_accepted(self):
        finding = self.by_uid("nozomi_many_vuln.json")["nozomi-CVE-2000-0002-asset-0002"]
        self.assertEqual(89, finding.cwe)

    def test_the_mitigation_prefers_the_latest_hotfix_then_the_minimum(self):
        findings = self.by_uid("nozomi_many_vuln.json")
        self.assertEqual("Apply hotfix 2.4.3.", findings["nozomi-nc-0001"].mitigation)
        self.assertEqual("Apply at least hotfix 5.0.1.",
                         findings["nozomi-CVE-2000-0002-asset-0002"].mitigation)
        self.assertIsNone(findings["nozomi-nc-0003"].mitigation)

    def test_the_summary_is_separated_from_the_asset_context_by_a_blank_line(self):
        finding = self.by_uid("nozomi_many_vuln.json")["nozomi-nc-0001"]
        self.assertIn("**Weakness:** Out-of-bounds Write\n\nA crafted control message",
                      finding.description)

    def test_a_record_with_no_summary_ends_at_the_asset_context(self):
        """No summary means no trailing blank line - the description simply ends at the last field."""
        finding = self.by_uid("nozomi_many_vuln.json")["nozomi-CVE-2000-0002-asset-0002"]
        self.assertTrue(finding.description.endswith("**Zone:** Cell Zone B"))
        self.assertNotIn("\n\n", finding.description)
        # The absent OS and the empty weakness name are both left out entirely.
        self.assertNotIn("**OS:**", finding.description)
        self.assertNotIn("**Weakness:**", finding.description)

    def test_an_empty_reference_list_leaves_the_references_unset(self):
        findings = self.by_uid("nozomi_many_vuln.json")
        self.assertIsNone(findings["nozomi-CVE-2000-0002-asset-0002"].references)
        self.assertIsNone(findings["nozomi-nc-0003"].references)

    def test_export_shapes(self):
        row = {"id": "nc-1", "cve": "CVE-2000-0001", "cve_score": 7.5}
        for payload in ([row], {"result": [row]}, {"results": [row]}, {"data": [row]}):
            with self.subTest(shape=str(payload)[:20]):
                self.assertEqual(1, len(self.parse_string(payload)))

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("Nozomi", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("result", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"result": [
            "not an object",
            None,
            {"id": "nc-9", "cve": "CVE-2000-0009", "cve_score": 5.0,
             "cve_references": "not a list"},
        ]})
        self.assertEqual(1, len(findings))
        self.assertEqual("nozomi-nc-9", findings[0].unique_id_from_tool)
        self.assertIsNone(findings[0].references)

    def test_the_component_is_the_ot_product(self):
        """The same CVE on two different devices stays two findings."""
        self.assertEqual(["title", "severity", "component_name"], NozomiParser().get_dedupe_fields())
        findings = self.by_uid("nozomi_many_vuln.json")
        self.assertEqual("GC-9000", findings["nozomi-nc-0001"].component_name)
        self.assertEqual("HMI-100", findings["nozomi-CVE-2000-0002-asset-0002"].component_name)
        self.assertIsNone(findings["nozomi-nc-0003"].component_name)

    def test_nothing_is_recorded_as_a_dynamic_finding(self):
        """
        Vantage builds its inventory passively, which is why it is used in OT at all.

        Recording a finding as dynamic would imply the device had been probed.
        """
        for finding in self.parse("nozomi_many_vuln.json"):
            with self.subTest(uid=finding.unique_id_from_tool):
                self.assertTrue(finding.static_finding)
                self.assertFalse(finding.dynamic_finding)

    def test_severity_is_always_a_known_value(self):
        for filename in ("nozomi_many_vuln.json", "nozomi_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
