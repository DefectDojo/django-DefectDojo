import io
import json
from datetime import date

from dojo.models import Finding, Test
from dojo.tools.automox.parser import AutomoxParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestAutomoxParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("automox") / filename
        with path.open(encoding="utf-8") as file:
            return list(AutomoxParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(AutomoxParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def row(self, **overrides):
        row = {"id": 1, "server_id": 1001, "installed": False, "name": "example-runtime",
               "display_name": "Example Runtime", "version": "1.0", "severity": "high"}
        row.update(overrides)
        return {"packages": [row]}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Automox connector's ScanTypeName verbatim.

        Note it does NOT follow the "<Vendor> - Connectors Import" pattern the other connector scan
        types use, so it cannot be derived - it has to be copied.
        """
        parser = AutomoxParser()
        self.assertEqual(["Automox Scan"], parser.get_scan_types())
        self.assertEqual("Automox Scan", parser.get_label_for_scan_types("Automox Scan"))
        self.assertNotIn("Automox - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("automox_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("automox_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's finding_converter."""
        findings = self.parse("automox_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Missing patch: Example Runtime", finding.title)
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("automox-900001", finding.unique_id_from_tool)
        self.assertEqual("example-runtime", finding.component_name)
        self.assertEqual("4.8.1", finding.component_version)
        self.assertEqual(8.8, finding.cvssv3_score)
        self.assertEqual(["CVE-2000-0001", "CVE-2000-0002"], finding.unsaved_vulnerability_ids)
        self.assertEqual(date(2024, 5, 13), finding.date)
        self.assertEqual("Install the available patch (version 4.8.1).", finding.mitigation)
        self.assertTrue(finding.active)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(["Windows", "requires-reboot"], finding.unsaved_tags)

        self.assertEqual(
            "**Package:** Example Runtime 4.8.1\n"
            "**Repository:** Vendor Update Catalog\n"
            "**Device:** generic-host-01\n"
            "**OS:** Windows Server 2019\n"
            "**CVEs:** CVE-2000-0001, CVE-2000-0002\n"
            "**Status:** Patch available but not installed",
            finding.description,
        )

    def test_many_vuln(self):
        """The two rows with no usable id are dropped; four remain."""
        self.assertEqual(4, len(self.parse("automox_many_vuln.json")))

    def test_the_device_comes_from_a_second_list_joined_on_server_id(self):
        """
        Automox reports the device separately from the missing patch.

        The connector pulls both endpoints and joins them, so an export has to carry both lists for a
        finding to name its device.
        """
        finding = self.by_uid("automox_many_vuln.json")["automox-900002"]
        self.assertIn("**Device:** generic-host-02", finding.description)
        self.assertIn("**OS:** Ubuntu 22.04", finding.description)
        self.assertIn("Linux", finding.unsaved_tags)

    def test_a_package_whose_device_is_absent_is_still_a_finding(self):
        """
        The connector's device lookup is a map read that can miss, and it converts anyway.

        Dropping the finding would silently lose a missing patch just because the device list did
        not travel with it.
        """
        finding = self.by_uid("automox_many_vuln.json")["automox-900003"]
        self.assertEqual("Missing patch: Example Agent", finding.title)
        self.assertNotIn("**Device:**", finding.description)
        self.assertNotIn("**OS:**", finding.description)
        self.assertEqual([], finding.unsaved_tags)

    def test_a_packages_only_export_is_accepted(self):
        """Automox answers the packages endpoint with a bare array, so a saved export is one."""
        findings = self.parse("automox_packages_only.json")
        self.assertEqual(1, len(findings))
        self.assertEqual("automox-900010", findings[0].unique_id_from_tool)
        self.assertNotIn("**Device:**", findings[0].description)

    def test_export_shapes(self):
        row = {"id": 1, "name": "example-runtime", "display_name": "Example Runtime",
               "version": "1.0", "severity": "low", "installed": False}
        for payload in ([row], {"packages": [row]}, {"data": [row]}, {"results": [row]}):
            with self.subTest(shape=str(payload)[:24]):
                self.assertEqual(1, len(self.parse_string(payload)))

    def test_the_devices_list_may_be_named_servers(self):
        """Automox serves devices from /servers, so an export may name the list either way."""
        row = {"id": 1, "server_id": 7, "name": "example", "display_name": "Example",
               "version": "1.0", "severity": "low", "installed": False}
        device = {"id": 7, "name": "generic-host-07", "os_family": "Linux"}
        for key in ("devices", "servers"):
            with self.subTest(key=key):
                findings = self.parse_string({"packages": [row], key: [device]})
                self.assertIn("**Device:** generic-host-07", findings[0].description)

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("Automox", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("packages", str(context.exception))

    def test_severity_labels(self):
        for label, expected in (("critical", "Critical"), ("high", "High"), ("medium", "Medium"),
                                ("low", "Low"), ("CRITICAL", "Critical"), (" high ", "High"),
                                ("none", "Info"), ("unknown", "Info"), ("no_known_cves", "Info"),
                                ("", "Info")):
            with self.subTest(label=label):
                findings = self.parse_string(self.row(severity=label))
                self.assertEqual(expected, findings[0].severity)

    def test_the_title_falls_back_to_the_package_name_then_the_id(self):
        findings = self.by_uid("automox_many_vuln.json")
        self.assertEqual("Missing patch: example-library", findings["automox-900002"].title)
        self.assertEqual("Missing patch: Automox package 900004", findings["automox-900004"].title)

    def test_quoted_numbers_are_accepted(self):
        """
        Automox's own decoder accepts a number sent as a quoted string, for ids and scores alike.

        A device id is quoted in the fixture too, so the join has to tolerate it on both sides.
        """
        finding = self.by_uid("automox_many_vuln.json")["automox-900002"]
        self.assertEqual(5.4, finding.cvssv3_score)
        self.assertIn("**Device:** generic-host-02", finding.description)

    def test_a_row_with_no_usable_id_is_dropped(self):
        """
        The id is the whole identity - every row without one would collapse onto "automox-0".

        Automox's own decoder rejects the entire page when an id is not numeric; dropping the single
        row keeps the rest of the export importable.
        """
        uids = self.by_uid("automox_many_vuln.json")
        self.assertNotIn("automox-0", uids)
        for finding in uids.values():
            self.assertNotIn("Dropped", finding.title)

    def test_a_non_numeric_score_is_zero_rather_than_an_error(self):
        """The connector's decoder tolerates a non-numeric score, so an import must not fail on one."""
        finding = self.by_uid("automox_many_vuln.json")["automox-900003"]
        self.assertEqual(0.0, finding.cvssv3_score)

    def test_blank_cves_are_dropped_and_no_cves_means_none(self):
        findings = self.by_uid("automox_many_vuln.json")
        self.assertEqual(["CVE-2000-0003", "CVE-2000-0004"],
                         findings["automox-900003"].unsaved_vulnerability_ids)
        self.assertIsNone(findings["automox-900002"].unsaved_vulnerability_ids)
        self.assertNotIn("**CVEs:**", findings["automox-900002"].description)

    def test_an_installed_package_reports_no_status_line(self):
        """The status line exists to say the patch is available and NOT applied."""
        findings = self.by_uid("automox_many_vuln.json")
        self.assertNotIn("**Status:**", findings["automox-900003"].description)
        self.assertIn("**Status:** Patch available but not installed",
                      findings["automox-900001"].description)

    def test_the_mitigation_names_the_version_only_when_there_is_one(self):
        findings = self.by_uid("automox_many_vuln.json")
        self.assertEqual("Install the available patch.", findings["automox-900003"].mitigation)
        self.assertEqual("Install the available patch (version 4.8.1).",
                         findings["automox-900001"].mitigation)

    def test_timestamp_formats(self):
        """Automox's own offset form first, then RFC 3339 - both with and without a colon."""
        cases = (
            ("2024-05-13T18:02:45+0000", date(2024, 5, 13)),
            ("2024-05-14T09:15:00Z", date(2024, 5, 14)),
            ("2024-06-01T00:00:00+02:00", date(2024, 6, 1)),
            ("2024-06-02T10:20:30.500000+0000", date(2024, 6, 2)),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                findings = self.parse_string(self.row(create_time=value))
                self.assertEqual(expected, findings[0].date)

    def test_an_unparseable_timestamp_leaves_the_date_alone(self):
        """Losing the finding over a malformed date would lose a real missing patch."""
        finding = self.by_uid("automox_many_vuln.json")["automox-900003"]
        self.assertEqual(date.today(), finding.date)

    def test_requires_reboot_is_tagged_only_when_true(self):
        findings = self.by_uid("automox_many_vuln.json")
        self.assertIn("requires-reboot", findings["automox-900001"].unsaved_tags)
        self.assertNotIn("requires-reboot", findings["automox-900002"].unsaved_tags)

    def test_the_severity_is_not_tagged_even_though_the_connector_comment_says_so(self):
        """
        The connector's tags() comment claims the severity is tagged; its code does not tag it.

        Mirroring the code rather than the comment is what keeps a file import and an API sync
        producing the same tags - flagged in the PR as a follow-up on the connector side.
        """
        finding = self.by_uid("automox_many_vuln.json")["automox-900001"]
        self.assertEqual(["Windows", "requires-reboot"], finding.unsaved_tags)
        self.assertNotIn("CRITICAL", finding.unsaved_tags)
        self.assertNotIn("Critical", finding.unsaved_tags)

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"packages": [
            "not an object",
            None,
            {"id": 5, "name": "example", "display_name": "Example", "version": "1.0",
             "severity": "low", "installed": False},
        ], "devices": ["not an object", None]})
        self.assertEqual(1, len(findings))
        self.assertEqual("automox-5", findings[0].unique_id_from_tool)

    def test_a_missing_cves_key_is_not_an_error(self):
        findings = self.parse_string(self.row(cves=None))
        self.assertIsNone(findings[0].unsaved_vulnerability_ids)

    def test_the_component_is_the_package(self):
        """
        The hash spans the component, so the same patch missing on two devices hashes alike.

        The package id in the identity is what keeps those two findings apart.
        """
        self.assertEqual(["title", "severity", "component_name"], AutomoxParser().get_dedupe_fields())
        finding = self.by_uid("automox_many_vuln.json")["automox-900001"]
        self.assertEqual("example-runtime", finding.component_name)
        self.assertEqual("4.8.1", finding.component_version)

    def test_a_package_with_no_name_has_no_component(self):
        findings = self.by_uid("automox_many_vuln.json")
        self.assertIsNone(findings["automox-900004"].component_name)

    def test_severity_is_always_a_known_value(self):
        for filename in ("automox_many_vuln.json", "automox_one_vuln.json",
                         "automox_packages_only.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
