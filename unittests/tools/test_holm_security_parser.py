import io
import json
from datetime import UTC, datetime

from dojo.models import Finding, Test
from dojo.tools.holm_security.parser import HolmSecurityParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestHolmSecurityParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("holm_security") / filename
        with path.open(encoding="utf-8") as file:
            return list(HolmSecurityParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(HolmSecurityParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def row(self, **overrides):
        row = {"hid": "HID-1", "vulnerability_name": "A finding", "severity": "high",
               "severity_level": 3, "status": "open", "asset_uuid": "asset-1"}
        row.update(overrides)
        return {"class": "web", "results": [row]}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Holm Security connector's ScanTypeName verbatim.

        Note it does NOT follow the "<Vendor> - Connectors Import" pattern the other connector scan
        types use, so it cannot be derived - it has to be copied.
        """
        parser = HolmSecurityParser()
        self.assertEqual(["Holm Security Scan"], parser.get_scan_types())
        self.assertEqual("Holm Security Scan", parser.get_label_for_scan_types("Holm Security Scan"))
        self.assertNotIn("Holm Security - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("holm_security_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("holm_security_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's finding_converter."""
        findings = self.parse("holm_security_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Cross-site scripting in the search form", finding.title)
        # The severity NAME wins over the numeric level, which here says Medium.
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("holm-HID-100001-asset-0001-443", finding.unique_id_from_tool)
        self.assertEqual("HID-100001", finding.vuln_id_from_tool)
        # The CVSS base wins over the score.
        self.assertEqual(6.1, finding.cvssv3_score)
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual("Encode user input before rendering it.", finding.mitigation)
        self.assertEqual("An attacker can run script in a visitor's session.", finding.impact)
        self.assertEqual("https://vendor.example.com/advisory/xss", finding.references)
        self.assertEqual(datetime(2024, 7, 1, tzinfo=UTC).date(), finding.date)
        self.assertTrue(finding.active)
        self.assertFalse(finding.static_finding)
        self.assertTrue(finding.dynamic_finding)
        self.assertEqual(["web-scan"], finding.unsaved_tags)

        self.assertEqual(
            "**Detection:** The payload was reflected in the response body.\n"
            "**Holm ID:** HID-100001\n"
            "**CVEs:** CVE-2000-0001\n"
            "**URL:** https://app.example.com/search?q=1\n"
            "**Port:** 443/tcp\n"
            "**Status:** open",
            finding.description,
        )

        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("app.example.com", locations[0].host)
        self.assertEqual("search", locations[0].path)

    def test_the_endpoint_is_the_url_alone_not_the_detected_port(self):
        """
        The connector puts only Holm's URL in the endpoint.

        The separately-reported detected_port is in the identity and the description instead, so an
        endpoint carries a port only when the URL itself names one. Adding it here would invent an
        endpoint the API path never produces.
        """
        finding = self.parse("holm_security_one_vuln.json")[0]
        location = self.get_unsaved_locations(finding)[0]
        self.assertFalse(location.port)
        self.assertIn("**Port:** 443/tcp", finding.description)
        self.assertIn("-443", finding.unique_id_from_tool)

    def test_a_url_naming_its_own_port_keeps_it(self):
        findings = self.parse_string(self.row(url="https://app.example.com:8443/thing"))
        location = self.get_unsaved_locations(findings[0])[0]
        self.assertEqual(8443, location.port)

    def test_the_asset_class_decides_static_versus_dynamic(self):
        """
        Holm scans two ways, and only the web class exercises a running application.

        The class is a property of the scan rather than the row, so an export states it - and without
        it the findings are static, which is the connector's own default for anything that is not the
        web class.
        """
        for asset_class, static, tags in (("web", False, ["web-scan"]),
                                          ("net", True, ["net-scan"]),
                                          ("", True, [])):
            with self.subTest(asset_class=asset_class):
                payload = {"results": [{"hid": "HID-1", "vulnerability_name": "A finding",
                                        "severity": "high", "status": "open"}]}
                if asset_class:
                    payload["class"] = asset_class
                findings = self.parse_string(payload)
                self.assertEqual(static, findings[0].static_finding)
                self.assertEqual(not static, findings[0].dynamic_finding)
                self.assertEqual(tags, findings[0].unsaved_tags)

    def test_many_vuln(self):
        self.assertEqual(5, len(self.parse("holm_security_many_vuln.json")))

    def test_severity_names(self):
        for name, expected in (("critical", "Critical"), ("high", "High"), ("medium", "Medium"),
                               ("low", "Low"), ("info", "Info"), ("HIGH", "High")):
            with self.subTest(name=name):
                findings = self.parse_string(self.row(severity=name, severity_level=0))
                self.assertEqual(expected, findings[0].severity)

    def test_the_numeric_level_is_the_fallback_and_four_is_the_most_severe(self):
        """
        Holm's numeric scale runs 0-4 with 4 the most severe - the inverse of a priority number.

        It is only consulted when the name is missing or unrecognised, so an unfamiliar name does not
        silently become Info while a usable level sits next to it.
        """
        for level, expected in ((4, "Critical"), (3, "High"), (2, "Medium"), (1, "Low"),
                                (0, "Info"), (5, "Info")):
            with self.subTest(level=level):
                findings = self.parse_string(self.row(severity="", severity_level=level))
                self.assertEqual(expected, findings[0].severity)

        findings = self.by_uid("holm_security_many_vuln.json")
        self.assertEqual("Critical", findings["holm-HID-100003-asset-0002"].severity)
        self.assertEqual("High", findings["holm-HID-100002-asset-0001-8443"].severity)

    def test_a_level_may_arrive_as_a_string(self):
        finding = self.by_uid("holm_security_many_vuln.json")["holm-HID-100002-asset-0001-8443"]
        self.assertEqual("High", finding.severity)

    def test_the_asset_and_port_are_part_of_the_identity(self):
        """
        Holm reports the same weakness once per host and once per listening port.

        Collapsing them would hide a second exposed service.
        """
        findings = self.by_uid("holm_security_many_vuln.json")
        self.assertIn("holm-HID-100001-asset-0001-443", findings)
        self.assertIn("holm-HID-100002-asset-0001-8443", findings)
        # No port reported, so it is left out of the identity rather than recorded as zero.
        self.assertIn("holm-HID-100003-asset-0002", findings)

    def test_the_cvss_base_wins_over_the_score(self):
        findings = self.by_uid("holm_security_many_vuln.json")
        self.assertEqual(6.1, findings["holm-HID-100001-asset-0001-443"].cvssv3_score)
        # No base, so the score stands in.
        self.assertEqual(7.5, findings["holm-HID-100002-asset-0001-8443"].cvssv3_score)
        self.assertEqual(0.0, findings["holm-HID-100003-asset-0002"].cvssv3_score)

    def test_title_falls_back_to_the_first_cve_then_the_holm_id(self):
        findings = self.by_uid("holm_security_many_vuln.json")
        self.assertEqual("CVE-2000-0002", findings["holm-HID-100002-asset-0001-8443"].title)

        bare = self.parse_string(self.row(vulnerability_name="", cve_ids=[]))
        self.assertEqual("Holm Security finding HID-1", bare[0].title)

    def test_closed_statuses_are_inactive(self):
        for status, active in (("open", True), ("fixed", False), ("closed", False),
                              ("resolved", False), ("FIXED", False), ("", True)):
            with self.subTest(status=status):
                findings = self.parse_string(self.row(status=status))
                self.assertEqual(active, findings[0].active)

    def test_the_port_label_carries_the_protocol(self):
        findings = self.by_uid("holm_security_many_vuln.json")
        self.assertIn("**Port:** 443/tcp", findings["holm-HID-100001-asset-0001-443"].description)
        # No protocol reported, so the port stands alone.
        self.assertIn("**Port:** 8443", findings["holm-HID-100002-asset-0001-8443"].description)
        self.assertNotIn("8443/", findings["holm-HID-100002-asset-0001-8443"].description)

    def test_a_finding_with_no_url_records_no_endpoint(self):
        """A network finding often has no URL, and the host stays in the description."""
        finding = self.by_uid("holm_security_many_vuln.json")["holm-HID-100003-asset-0002"]
        self.assertEqual([], self.get_unsaved_locations(finding))
        self.assertNotIn("**URL:**", finding.description)

    def test_a_url_that_cannot_be_a_host_is_not_recorded(self):
        finding = self.by_uid("holm_security_many_vuln.json")["holm-HID-100005-asset-0003"]
        self.assertEqual([], self.get_unsaved_locations(finding))
        self.assertIn("**URL:** an internal service", finding.description)

    def test_the_date_prefers_the_last_detection(self):
        findings = self.by_uid("holm_security_many_vuln.json")
        self.assertEqual(
            datetime(2024, 7, 1, tzinfo=UTC).date(),
            findings["holm-HID-100001-asset-0001-443"].date,
        )
        # No last_detected, so the first detection stands in.
        self.assertEqual(
            datetime(2024, 6, 1, tzinfo=UTC).date(),
            findings["holm-HID-100002-asset-0001-8443"].date,
        )

    def test_no_detection_dates_keeps_the_default(self):
        finding = self.by_uid("holm_security_many_vuln.json")["holm-HID-100003-asset-0002"]
        self.assertEqual(datetime.now(tz=UTC).date(), finding.date)

    def test_a_bare_list_of_vulnerabilities_is_accepted(self):
        findings = self.parse_string([
            {"hid": "HID-1", "vulnerability_name": "A finding", "severity": "high", "status": "open"},
        ])
        self.assertEqual(1, len(findings))
        # No class stated, so static, matching the connector's default.
        self.assertTrue(findings[0].static_finding)

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("Holm Security", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("results", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"class": "web", "results": [
            "not an object",
            None,
            {"hid": "HID-1", "vulnerability_name": "A finding", "severity": "high", "status": "open"},
        ]})
        self.assertEqual(1, len(findings))

    def test_severity_is_always_a_known_value(self):
        for filename in ("holm_security_many_vuln.json", "holm_security_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
