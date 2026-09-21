import io
import json
from datetime import date

from dojo.models import Finding, Test
from dojo.tools.accuknox.parser import AccuKnoxParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestAccuKnoxParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("accuknox") / filename).open(encoding="utf-8") as file:
            return list(AccuKnoxParser().get_findings(file, Test()))

    def by_uid(self, filename):
        return {f.unique_id_from_tool: f for f in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the AccuKnox connector's ScanType() verbatim.

        Any drift and a customer who uploads an export and also syncs the API gets two
        un-deduplicated copies of every finding.
        """
        parser = AccuKnoxParser()
        self.assertEqual(["AccuKnox - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "AccuKnox - Connectors Import",
            parser.get_label_for_scan_types("AccuKnox - Connectors Import"),
        )

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("accuknox_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("accuknox_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring RowToFinding in the connector's converter."""
        findings = self.parse("accuknox_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("CVE-2000-0001 in openssl", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("af-0000000001", finding.unique_id_from_tool)
        self.assertEqual("container_image", finding.vuln_id_from_tool)
        self.assertEqual("openssl", finding.component_name)
        self.assertEqual("3.0.11-1", finding.component_version)
        self.assertEqual("registry.example.com/generic-api:1.4.0", finding.service)
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual("Rebuild the image on a patched base.", finding.mitigation)
        self.assertEqual(date(2026, 7, 20), finding.date)
        self.assertTrue(finding.active)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

    def test_the_column_names_vary_by_data_type(self):
        """
        AccuKnox returns container, IaC, cloud-posture and runtime rows through ONE endpoint, and the
        column names differ per type.

        AccuKnox does not publish this part of its schema, so the connector probes a list of candidate
        keys per field. Assuming a single set of names would silently import empty findings for every
        type but one - the fixture's second row uses id/title/severity/finding_status where the first
        uses finding_id/name/risk_factor/status.
        """
        findings = self.by_uid("accuknox_many_vuln.json")

        first = findings["af-0000000001"]     # finding_id / name / risk_factor / status
        self.assertEqual("CVE-2000-0001 in openssl", first.title)
        self.assertEqual("Critical", first.severity)

        second = findings["af-0000000002"]    # id / title / severity / finding_status
        self.assertEqual("S3 bucket is publicly readable", second.title)
        self.assertEqual("High", second.severity)
        self.assertEqual("generic-app-assets", second.service)
        self.assertEqual("Remove the public grant.", second.mitigation)

    def test_the_vulnerability_column_prefix_is_also_tried(self):
        """
        Some AccuKnox rows prefix their vulnerability columns with "vulnerability__".

        Every candidate key is tried both bare and prefixed, so a prefixed row still maps. Without
        that the whole row would import as an empty Info finding.
        """
        finding = self.by_uid("accuknox_many_vuln.json")["af-0000000003"]
        self.assertEqual("CVE-2000-0002 in curl", finding.title)
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("curl", finding.component_name)
        self.assertEqual("7.81.0-1", finding.component_version)
        self.assertEqual(["CVE-2000-0002"], finding.unsaved_vulnerability_ids)
        self.assertIn("A flaw in URL parsing.", finding.description)

    def test_the_status_decides_which_findings_are_closed(self):
        """
        Only fixed, accepted-risk and duplicate close a finding.

        The working states - active, in progress, waiting for 3rd party, exception requested - stay
        open, so a finding somebody is mid-way through fixing is not hidden.
        """
        findings = self.by_uid("accuknox_many_vuln.json")

        self.assertTrue(findings["af-0000000001"].active)     # active
        self.assertTrue(findings["af-0000000002"].active)     # in progress

        fixed = findings["af-0000000003"]
        self.assertFalse(fixed.active)
        self.assertTrue(fixed.is_mitigated)

        accepted = findings["af-0000000004"]
        self.assertFalse(accepted.active)
        self.assertTrue(accepted.risk_accepted)

        duplicate = findings["af-0000000005"]
        self.assertFalse(duplicate.active)
        self.assertTrue(duplicate.duplicate)

    def test_only_potential_is_unverified_and_a_blank_status_counts_as_verified(self):
        """
        The connector's rule: verified unless the status is empty or "potential".

        A row with no status at all is treated as verified, which is the opposite of what a naive
        truthiness check would give.
        """
        findings = self.by_uid("accuknox_many_vuln.json")
        self.assertFalse(findings["af-0000000006"].verified)   # potential
        self.assertFalse(findings["af-0000000007"].verified)   # blank status
        self.assertTrue(findings["af-0000000001"].verified)    # active

    def test_the_status_helper_directly(self):
        parser = AccuKnoxParser()
        for status, checks in (
            ("active", {"active": True, "verified": True}),
            ("in progress", {"active": True, "verified": True}),
            ("waiting for 3rd party", {"active": True, "verified": True}),
            ("exception requested", {"active": True, "verified": True}),
            ("waiting for verification", {"active": True, "verified": True}),
            ("fixed", {"active": False, "is_mitigated": True}),
            ("accepted risk", {"active": False, "risk_accepted": True}),
            ("duplicate", {"active": False, "duplicate": True}),
            ("potential", {"active": True, "verified": False}),
            ("", {"active": True, "verified": False}),
        ):
            finding = Finding()
            parser.apply_status(finding, status)
            for attribute, expected in checks.items():
                self.assertEqual(expected, getattr(finding, attribute), f"{status!r}.{attribute}")

    def test_an_ignored_row_is_marked_out_of_scope_rather_than_dropped(self):
        """
        AccuKnox lets a user suppress a row, and the connector records that instead of discarding it.

        The flag arrives as a string in this row, so a bare boolean check would miss it.
        """
        finding = self.by_uid("accuknox_many_vuln.json")["af-0000000006"]
        self.assertTrue(finding.out_of_scope)

    def test_a_not_ignored_row_is_not_out_of_scope(self):
        finding = self.by_uid("accuknox_many_vuln.json")["af-0000000001"]
        self.assertFalse(finding.out_of_scope)

    def test_the_ignored_flag_accepts_both_boolean_and_string_forms(self):
        parser = AccuKnoxParser()
        for value, expected in [
            (True, True), ("true", True), ("True", True), ("yes", True), ("1", True),
            (1, True), (False, False), ("false", False), ("", False), (0, False),
        ]:
            self.assertEqual(expected, parser.flag({"ignored": value}, ("ignored",)), value)
        self.assertFalse(parser.flag({}, ("ignored",)))

    def test_an_unrecognised_risk_factor_is_info(self):
        finding = self.by_uid("accuknox_many_vuln.json")["af-0000000006"]
        self.assertEqual("Info", finding.severity)

    def test_a_row_with_no_title_is_named_from_its_id(self):
        """
        AccuKnox does not publish the schema for every data type, so a row can carry no recognisable
        title and still has to import.
        """
        finding = self.by_uid("accuknox_many_vuln.json")["af-0000000007"]
        self.assertEqual("AccuKnox finding af-0000000007", finding.title)

    def test_a_row_with_neither_title_nor_id_still_imports(self):
        report = io.StringIO(json.dumps({"results": [{"data_type": "runtime"}]}))
        finding = list(AccuKnoxParser().get_findings(report, Test()))[0]
        self.assertEqual("AccuKnox finding", finding.title)
        self.assertIsNone(finding.unique_id_from_tool)

    def test_a_cve_list_column_is_scanned_and_deduplicated(self):
        """
        The CVE column can hold several identifiers, and AccuKnox sometimes sends an array.

        The fixture repeats one to prove the deduplication.
        """
        finding = self.by_uid("accuknox_many_vuln.json")["af-0000000007"]
        self.assertEqual(["CVE-2000-0003", "CVE-2000-0004"], finding.unsaved_vulnerability_ids)

    def test_the_cve_falls_back_to_the_title(self):
        """AccuKnox often carries the identifier only in the finding name."""
        report = io.StringIO(json.dumps({"results": [
            {"finding_id": "x", "name": "CVE-2000-0009 in openssl", "risk_factor": "high"},
        ]}))
        finding = list(AccuKnoxParser().get_findings(report, Test()))[0]
        self.assertEqual(["CVE-2000-0009"], finding.unsaved_vulnerability_ids)

    def test_a_row_with_no_cve_anywhere_has_none(self):
        finding = self.by_uid("accuknox_many_vuln.json")["af-0000000004"]
        self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_the_description_carries_the_class_status_and_asset(self):
        finding = self.parse("accuknox_one_vuln.json")[0]
        self.assertIn("The image ships a vulnerable openssl.", finding.description)
        self.assertIn("**Finding class:** container_image", finding.description)
        self.assertIn("**AccuKnox status:** active", finding.description)
        self.assertIn("**Asset:** registry.example.com/generic-api:1.4.0", finding.description)
        self.assertIn("**Asset type:** image", finding.description)
        self.assertIn("**First seen:** 2026-07-20", finding.description)
        self.assertIn("**Last seen:** 2026-07-31", finding.description)

    def test_tags_are_the_data_type_and_asset_type(self):
        finding = self.parse("accuknox_one_vuln.json")[0]
        self.assertEqual(["container_image", "image"], finding.unsaved_tags)

    def test_the_alternative_date_formats_are_accepted(self):
        findings = self.by_uid("accuknox_many_vuln.json")
        self.assertEqual(date(2026, 7, 21), findings["af-0000000002"].date)  # "2026-07-21 10:00:00"
        self.assertEqual(date(2026, 7, 22), findings["af-0000000003"].date)  # "2026-07-22"
        self.assertIsNone(findings["af-0000000004"].date)                    # no date column

    def test_a_bare_array_is_accepted(self):
        report = io.StringIO(json.dumps([
            {"finding_id": "x", "name": "A finding", "risk_factor": "low"},
        ]))
        self.assertEqual(1, len(list(AccuKnoxParser().get_findings(report, Test()))))

    def test_many_vuln(self):
        self.assertEqual(7, len(self.parse("accuknox_many_vuln.json")))

    def test_an_unexpected_shape_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(AccuKnoxParser().get_findings(io.StringIO('"nope"'), Test()))
        self.assertIn("results", str(raised.exception))
