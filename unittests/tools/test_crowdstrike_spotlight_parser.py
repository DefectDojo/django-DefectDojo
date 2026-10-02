import io
import json
from datetime import date

from dojo.models import Finding, Test
from dojo.tools.crowdstrike_spotlight.parser import CrowdstrikeSpotlightParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestCrowdstrikeSpotlightParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("crowdstrike_spotlight") / filename
        with path.open(encoding="utf-8") as file:
            return list(CrowdstrikeSpotlightParser().get_findings(file, Test()))

    def by_uid(self, filename):
        return {f.unique_id_from_tool: f for f in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal ScanTypeSpotlight in the CrowdStrike connector verbatim.

        Any drift and a customer who uploads an export and also syncs the API gets two
        un-deduplicated copies of every finding, because the two land in different test types. Note
        the connector also defines a separate "CrowdStrike:Detections - Connectors Import" scan type,
        which this parser must not claim.
        """
        parser = CrowdstrikeSpotlightParser()
        self.assertEqual(["CrowdStrike:Spotlight - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "CrowdStrike:Spotlight - Connectors Import",
            parser.get_label_for_scan_types("CrowdStrike:Spotlight - Connectors Import"),
        )
        self.assertNotIn(
            "CrowdStrike:Detections - Connectors Import", parser.get_scan_types(),
        )

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("crowdstrike_spotlight_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("crowdstrike_spotlight_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring VulnConverter.Convert in the connector."""
        findings = self.parse("crowdstrike_spotlight_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        # converter title(): "<CVE>: <product_name_version>"
        self.assertEqual("CVE-2000-0001: OpenSSL 3.0.11", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("spotlight-0000000000000000000000000000001", finding.unique_id_from_tool)
        self.assertEqual("CVE-2000-0001", finding.vuln_id_from_tool)
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual("OpenSSL", finding.component_name)
        # converter componentVersion(): product_name_version minus the normalized name.
        self.assertEqual("3.0.11", finding.component_version)
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", finding.cvssv3)
        # converter firstCWE(): the first parseable CWE-NNN.
        self.assertEqual(295, finding.cwe)
        self.assertEqual(date(2026, 1, 15), finding.date)

        # The converter marks Spotlight findings NEITHER static NOR dynamic.
        self.assertFalse(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

    def test_the_description_mirrors_the_converters_block(self):
        finding = self.parse("crowdstrike_spotlight_one_vuln.json")[0]
        self.assertIn("A flaw in certificate verification", finding.description)
        self.assertIn("**Host:** host01.example.com", finding.description)
        self.assertIn("**OS:** Ubuntu 22.04", finding.description)
        self.assertIn("**Affected product:** OpenSSL 3.0.11", finding.description)
        self.assertIn("**ExPRT rating:** HIGH", finding.description)
        self.assertIn(
            "**CISA KEV:** listed in the CISA Known Exploited Vulnerabilities catalog",
            finding.description,
        )

    def test_the_severity_justification_mirrors_the_converters_sentence(self):
        """The converter's severityJustification(): markdown emphasis and a one-decimal score."""
        finding = self.parse("crowdstrike_spotlight_one_vuln.json")[0]
        self.assertEqual(
            "CrowdStrike severity of **CRITICAL** from a base CVSS score of **9.8** "
            "(ExPRT rating: HIGH)",
            finding.severity_justification,
        )

    def test_mitigation_and_references_mirror_the_converter(self):
        finding = self.parse("crowdstrike_spotlight_one_vuln.json")[0]
        self.assertEqual(
            "**Update OpenSSL**\nUpgrade OpenSSL to 3.0.13 or later.\n"
            "Reference: VENDOR-SA-2026-0001",
            finding.mitigation,
        )
        # converter references(): CVE references, then vendor advisories, then entity links.
        self.assertEqual(
            "https://example.com/advisories/cve-2000-0001\n"
            "https://vendor.example.com/security/2000-0001\n"
            "https://example.com/remediation/openssl\n"
            "https://vendor.example.com/downloads/openssl",
            finding.references,
        )

    def test_tags_mirror_the_converter(self):
        finding = self.parse("crowdstrike_spotlight_one_vuln.json")[0]
        self.assertEqual(
            ["exprt:high", "cisa-kev", "env/production", "team/platform"],
            finding.unsaved_tags,
        )

    def test_the_affected_host_is_recorded(self):
        """
        The connector emits "//<host>" so DefectDojo's URI parser treats it as a host.

        Asserted through get_unsaved_locations so this passes with V3_FEATURE_LOCATIONS either way -
        Finding.__init__ creates unsaved_locations or unsaved_endpoints, never both.
        """
        finding = self.parse("crowdstrike_spotlight_one_vuln.json")[0]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("host01.example.com", locations[0].host)

    def test_the_host_falls_back_to_the_local_ip(self):
        """The converter's hostEndpoint(): hostname first, then local_ip."""
        finding = self.by_uid("crowdstrike_spotlight_many_vuln.json")["spotlight-3"]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("10.0.0.33", locations[0].host)

    def test_the_severity_ladder_is_the_connectors(self):
        """
        The converter's mapCVESeverity(): upper-cased comparison, anything unrecognised is Info.

        Spotlight reports severity on the CVE, not the vulnerability, so an unrecognised value must
        not silently inherit a neighbouring finding's grade.
        """
        findings = self.by_uid("crowdstrike_spotlight_many_vuln.json")
        self.assertEqual("Critical", findings["spotlight-0000000000000000000000000000001"].severity)
        self.assertEqual("High", findings["spotlight-2"].severity)
        self.assertEqual("Medium", findings["spotlight-3"].severity)
        self.assertEqual("Low", findings["spotlight-4"].severity)
        self.assertEqual("Info", findings["spotlight-5"].severity)

    def test_a_vulnerability_with_no_apps_has_no_component(self):
        finding = self.by_uid("crowdstrike_spotlight_many_vuln.json")["spotlight-4"]
        self.assertEqual("CVE-2000-0004", finding.title)
        self.assertIsNone(finding.component_name)
        self.assertIsNone(finding.component_version)
        self.assertIsNone(finding.mitigation)

    def test_an_unparseable_cwe_list_yields_zero_not_a_crash(self):
        """
        The converter's firstCWE(): entries that do not split into two parts, or whose tail is not a
        number, are skipped; zero is returned when none parse.

        Finding.cwe is an IntegerField with default 0, so "no CWE" reads as 0 rather than None.
        """
        finding = self.by_uid("crowdstrike_spotlight_many_vuln.json")["spotlight-4"]
        self.assertEqual(0, finding.cwe)

    def test_a_vulnerability_with_neither_cve_nor_product_uses_the_constant_title(self):
        finding = self.by_uid("crowdstrike_spotlight_many_vuln.json")["spotlight-5"]
        self.assertEqual("CrowdStrike Spotlight Vulnerability", finding.title)
        self.assertIsNone(finding.vuln_id_from_tool)
        # Finding.__init__ leaves this None; "no CVE" is None, not an empty list.
        self.assertIsNone(finding.unsaved_vulnerability_ids)
        self.assertIsNone(finding.references)

    def test_an_unparseable_timestamp_leaves_the_date_unset(self):
        """The converter's formatDate() returns "" when the RFC3339 parse fails."""
        finding = self.by_uid("crowdstrike_spotlight_many_vuln.json")["spotlight-5"]
        self.assertIsNone(finding.date)

    def test_a_zero_base_score_is_left_out_of_the_justification(self):
        finding = self.by_uid("crowdstrike_spotlight_many_vuln.json")["spotlight-5"]
        self.assertEqual(
            "CrowdStrike severity of **NOT-A-SEVERITY**", finding.severity_justification,
        )
        self.assertIsNone(finding.cvssv3_score)

    def test_several_remediation_entities_are_separated_by_a_blank_line(self):
        finding = self.by_uid("crowdstrike_spotlight_many_vuln.json")["spotlight-6"]
        self.assertEqual(
            "**Apply patch**\nInstall KB0000001.\nReference: KB0000001\n\n"
            "**Workaround**\nDisable the affected feature.",
            finding.mitigation,
        )

    def test_a_bare_array_is_accepted(self):
        report = io.StringIO(json.dumps([{
            "id": "v1", "cve": {"id": "CVE-2000-0001", "severity": "HIGH"},
        }]))
        findings = list(CrowdstrikeSpotlightParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("CVE-2000-0001", findings[0].title)

    def test_a_repeated_vulnerability_id_collapses(self):
        row = {"id": "same", "cve": {"id": "CVE-2000-0001", "severity": "HIGH"}}
        report = io.StringIO(json.dumps({"resources": [row, row]}))
        self.assertEqual(1, len(list(CrowdstrikeSpotlightParser().get_findings(report, Test()))))

    def test_an_unexpected_shape_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(CrowdstrikeSpotlightParser().get_findings(io.StringIO('"nope"'), Test()))
        self.assertIn("resources", str(raised.exception))
