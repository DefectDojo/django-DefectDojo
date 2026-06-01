from dojo.models import Test
from dojo.tools.alertlogic.parser import AlertlogicParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestAlertlogicParser(DojoTestCase):

    @staticmethod
    def _findings(filename):
        with (get_unit_tests_scans_path("alertlogic") / filename).open(encoding="utf-8") as testfile:
            return AlertlogicParser().get_findings(testfile, Test())

    def test_get_scan_types(self):
        self.assertEqual(["Alert Logic Scan"], AlertlogicParser().get_scan_types())

    def test_get_label_for_scan_types(self):
        self.assertEqual("Alert Logic Scan", AlertlogicParser().get_label_for_scan_types("Alert Logic Scan"))

    def test_get_description_for_scan_types(self):
        description = AlertlogicParser().get_description_for_scan_types("Alert Logic Scan")
        self.assertIn("Alert Logic", description)

    def test_parse_no_findings(self):
        self.assertEqual(0, len(self._findings("no_vuln.csv")))

    def test_parse_one_finding(self):
        self.assertEqual(1, len(self._findings("one_vuln.csv")))

    def test_parse_many_findings(self):
        self.assertEqual(7, len(self._findings("many_vulns.csv")))

    def test_one_finding_basic_fields(self):
        finding = self._findings("one_vuln.csv")[0]
        self.assertEqual("CVE-2023-44487 - HTTP/2 Rapid Reset Attack", finding.title)
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("web-01.example.com", finding.component_name)
        self.assertEqual("11111111111111111111111111111111", finding.unique_id_from_tool)
        self.assertEqual(5.3, finding.cvssv3_score)
        self.assertEqual(True, finding.static_finding)
        self.assertEqual(False, finding.dynamic_finding)

    def test_one_finding_cve(self):
        finding = self._findings("one_vuln.csv")[0]
        self.assertEqual(["CVE-2023-44487"], finding.unsaved_vulnerability_ids)

    def test_one_finding_mitigation(self):
        finding = self._findings("one_vuln.csv")[0]
        self.assertIn("nginx", finding.mitigation)
        self.assertIn("Apache httpd", finding.mitigation)

    def test_one_finding_description_includes_evidence_and_os(self):
        finding = self._findings("one_vuln.csv")[0]
        self.assertIn("**Description:**", finding.description)
        self.assertIn("**Evidence:**", finding.description)
        self.assertIn("**Operating System:**", finding.description)
        self.assertIn("**Vulnerability ID:**", finding.description)

    def test_severity_critical(self):
        finding = self._findings("many_vulns.csv")[0]
        self.assertEqual("Critical", finding.severity)

    def test_severity_high(self):
        finding = self._findings("many_vulns.csv")[1]
        self.assertEqual("High", finding.severity)

    def test_severity_low(self):
        finding = self._findings("many_vulns.csv")[2]
        self.assertEqual("Low", finding.severity)

    def test_severity_info(self):
        finding = self._findings("many_vulns.csv")[3]
        self.assertEqual("Info", finding.severity)

    def test_severity_medium(self):
        finding = self._findings("many_vulns.csv")[6]
        self.assertEqual("Medium", finding.severity)

    def test_title_truncation_long(self):
        # Row 4 has an 841-char Vulnerability value, should be truncated to 500
        finding = self._findings("many_vulns.csv")[4]
        self.assertEqual(500, len(finding.title))
        self.assertTrue(finding.title.endswith("..."))

    def test_title_no_truncation_when_short(self):
        # Row 0 has a 51-char title — should not be truncated
        finding = self._findings("many_vulns.csv")[0]
        self.assertFalse(finding.title.endswith("..."))
        self.assertEqual(51, len(finding.title))

    def test_unique_id_from_tool(self):
        # Distinct unique_id per finding — these are the canonical dedup anchors
        findings = self._findings("many_vulns.csv")
        ids = [f.unique_id_from_tool for f in findings]
        self.assertEqual(len(ids), len(set(ids)))  # all unique
        self.assertEqual("22222222222222222222222222222222", findings[0].unique_id_from_tool)

    def test_endpoint_single_ipv4(self):
        # Row 0 has a single IPv4 address
        finding = self._findings("many_vulns.csv")[0]
        endpoints = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(endpoints))
        endpoint = endpoints[0]
        self.assertEqual("192.0.2.20", endpoint.host)
        self.assertEqual("tcp", endpoint.protocol)
        self.assertEqual(8080, endpoint.port)

    def test_endpoint_multi_ipv4_and_ipv6(self):
        # Row 1: "198.51.100.30, fe80::250:56ff:fe96:b97"
        finding = self._findings("many_vulns.csv")[1]
        endpoints = self.get_unsaved_locations(finding)
        self.assertEqual(2, len(endpoints))
        hosts = {ep.host for ep in endpoints}
        self.assertEqual({"198.51.100.30", "fe80::250:56ff:fe96:b97"}, hosts)

    def test_endpoint_ipv6_only(self):
        # Row 6 has IPv6-only address
        finding = self._findings("many_vulns.csv")[6]
        endpoints = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(endpoints))
        self.assertEqual("2001:db8::1:80", endpoints[0].host)

    def test_endpoint_port_zero_is_omitted(self):
        # Row 2 has Protocol/Port "TCP/0" — port should not be set
        finding = self._findings("many_vulns.csv")[2]
        endpoints = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(endpoints))
        self.assertIsNone(endpoints[0].port)

    def test_endpoint_clean_succeeds(self):
        # Hard guardrail: every endpoint/location must pass clean()
        # (get_unsaved_locations cleans each entry internally)
        self.validate_locations(self._findings("many_vulns.csv"))

    def test_cve_present(self):
        # Row 0 has CVE-2021-44228 (Log4Shell)
        finding = self._findings("many_vulns.csv")[0]
        self.assertEqual(["CVE-2021-44228"], finding.unsaved_vulnerability_ids)

    def test_cve_absent(self):
        # Row 2 (TCP Timestamp) has no CVE — attribute should be unset or empty
        finding = self._findings("many_vulns.csv")[2]
        self.assertFalse(getattr(finding, "unsaved_vulnerability_ids", None))

    def test_cisa_known_exploited_tag_added(self):
        # Rows 0, 1, 4 have CISA KEV = "Yes"
        findings = self._findings("many_vulns.csv")
        self.assertIn("cisa-known-exploited", findings[0].unsaved_tags)
        self.assertIn("cisa-known-exploited", findings[1].unsaved_tags)
        self.assertIn("cisa-known-exploited", findings[4].unsaved_tags)

    def test_cisa_known_exploited_tag_not_added(self):
        # Row 2 has CISA KEV = "No" — no tag should be added
        finding = self._findings("many_vulns.csv")[2]
        self.assertFalse(getattr(finding, "unsaved_tags", None))

    def test_cvssv3_score_parsed(self):
        finding = self._findings("many_vulns.csv")[0]
        self.assertEqual(10.0, finding.cvssv3_score)

    def test_cvssv3_score_empty_is_none(self):
        # Row 6 has empty CVSS Score
        finding = self._findings("many_vulns.csv")[6]
        self.assertIsNone(finding.cvssv3_score)

    def test_static_dynamic_flags_set_explicitly(self):
        for finding in self._findings("many_vulns.csv"):
            self.assertEqual(True, finding.static_finding)
            self.assertEqual(False, finding.dynamic_finding)

    def test_bom_handling(self):
        # All fixtures have a UTF-8 BOM; the parser must consume it without
        # producing a phantom field name with the BOM prefix.
        finding = self._findings("one_vuln.csv")[0]
        self.assertEqual("CVE-2023-44487 - HTTP/2 Rapid Reset Attack", finding.title)
        # If BOM were not stripped, the first column key would be "﻿Vulnerability"
        # and finding.title would be empty.

    def test_multiline_field_preserved_in_description(self):
        # Row 0 (Log4Shell) has a multi-line Description field
        finding = self._findings("many_vulns.csv")[0]
        self.assertIn("Log4Shell", finding.description)
        self.assertIn("\n", finding.description)
