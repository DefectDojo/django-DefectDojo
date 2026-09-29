import io
import json
from datetime import UTC, datetime

from dojo.models import Finding, Test
from dojo.tools.fleet_vulnerabilities.parser import FleetVulnerabilitiesParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestFleetVulnerabilitiesParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("fleet_vulnerabilities") / filename
        with path.open(encoding="utf-8") as file:
            return list(FleetVulnerabilitiesParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(FleetVulnerabilitiesParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Fleet connector's ScanTypeVulnerabilities verbatim.

        Any drift and a customer who uploads an export and also syncs the API gets two
        un-deduplicated copies of every CVE.
        """
        parser = FleetVulnerabilitiesParser()
        self.assertEqual(["Fleet:Vulnerabilities - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "Fleet:Vulnerabilities - Connectors Import",
            parser.get_label_for_scan_types("Fleet:Vulnerabilities - Connectors Import"),
        )
        self.assertNotIn("Fleet:Policies - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        """
        Software with no CVEs produces nothing.

        The sample also carries a *failing* policy, which this parser must ignore: policies are a
        separate scan type with their own deduplication key.
        """
        self.assertEqual(0, len(self.parse("fleet_vulnerabilities_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("fleet_vulnerabilities_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring vulnerabilityFinding in the connector's converter."""
        findings = self.parse("fleet_vulnerabilities_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("CVE-2000-0001 - Example Browser 120.0.1 on laptop-11", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertEqual("Example Browser", finding.component_name)
        self.assertEqual("120.0.1", finding.component_version)
        self.assertEqual("CVE-2000-0001", finding.vuln_id_from_tool)
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual("11:Example Browser:120.0.1:CVE-2000-0001", finding.unique_id_from_tool)
        self.assertEqual(datetime(2024, 5, 1, tzinfo=UTC).date(), finding.publish_date)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(
            "Upgrade Example Browser to 120.0.2 or later, which resolves this CVE.",
            finding.mitigation,
        )
        self.assertEqual(["cisa-known-exploited", "darwin", "endpoint", "vulnerability"], finding.unsaved_tags)

        sections = finding.description.split("\n\n")
        self.assertEqual("A memory-safety flaw allows remote code execution.", sections[0])
        self.assertEqual("**Software:** Example Browser 120.0.1 (apps, Example Vendor)", sections[1])
        self.assertEqual("**Host:** laptop-11 (10.0.0.11)", sections[2])
        self.assertEqual("**OS:** darwin macOS 14.5", sections[3])
        self.assertIn("**CPE:** cpe:2.3:a:example:browser", sections[4])
        self.assertEqual("**CVSS:** 9.8", sections[5])
        self.assertEqual(
            "**EPSS:** 0.94 (probability of exploitation in the next 30 days)",
            sections[6],
        )
        self.assertIn("**CISA KEV:**", sections[7])

        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("laptop-11", locations[0].host)

    def test_many_vuln(self):
        """One finding per host per software per CVE, and the CVE-less row is dropped."""
        self.assertEqual(7, len(self.parse("fleet_vulnerabilities_many_vuln.json")))

    def test_the_same_cve_on_two_hosts_is_two_findings(self):
        """
        Fleet reports software per host, so the host is part of the identity.

        Collapsing them would hide a machine that is still running the vulnerable version.
        """
        findings = self.by_uid("fleet_vulnerabilities_many_vuln.json")
        self.assertIn("11:Example Browser:120.0.1:CVE-2000-0001", findings)
        self.assertIn("12:openssl:3.0.2:CVE-2000-0001", findings)
        self.assertEqual("Example Browser", findings["11:Example Browser:120.0.1:CVE-2000-0001"].component_name)
        self.assertEqual("openssl", findings["12:openssl:3.0.2:CVE-2000-0001"].component_name)

    def test_severity_floors(self):
        for score, expected in ((10.0, "Critical"), (9.0, "Critical"), (8.9, "High"), (7.0, "High"),
                                (6.9, "Medium"), (4.0, "Medium"), (3.9, "Low"), (0.1, "Low"),
                                (0, "Info")):
            with self.subTest(score=score):
                findings = self.parse_string({"hosts": [{"id": 1, "hostname": "h.example.com", "software": [
                    {"name": "pkg", "version": "1.0", "vulnerabilities": [
                        {"cve": "CVE-2000-0001", "cvss_score": score},
                    ]},
                ]}]})
                self.assertEqual(expected, findings[0].severity)

    def test_an_unscored_cve_is_medium(self):
        """
        A CVE Fleet has not scored is Medium, not Info.

        Fleet enriches from the NVD, so a missing score means "not scored yet" rather than "no risk",
        and the connector deliberately grades it as an unknown. An explicit zero is still Info.
        """
        findings = self.by_uid("fleet_vulnerabilities_many_vuln.json")
        self.assertEqual("Medium", findings["11:Example Reader:9.1:CVE-2000-0006"].severity)
        self.assertIsNone(findings["11:Example Reader:9.1:CVE-2000-0006"].cvssv3_score)
        self.assertEqual("Info", findings["11:Example Reader:9.1:CVE-2000-0005"].severity)
        self.assertEqual(0, findings["11:Example Reader:9.1:CVE-2000-0005"].cvssv3_score)

    def test_a_null_score_is_unscored_but_an_empty_string_is_zero(self):
        """This is the connector's own FlexFloat decoding, which distinguishes the two."""
        findings = self.parse_string({"hosts": [{"id": 1, "hostname": "h.example.com", "software": [
            {"name": "pkg", "version": "1.0", "vulnerabilities": [
                {"cve": "CVE-2000-0001", "cvss_score": None},
                {"cve": "CVE-2000-0002", "cvss_score": ""},
            ]},
        ]}]})
        self.assertEqual("Medium", findings[0].severity)
        self.assertEqual("Info", findings[1].severity)

    def test_numbers_may_arrive_as_strings(self):
        """Fleet sends these as either a number or a numeric string."""
        finding = self.by_uid("fleet_vulnerabilities_many_vuln.json")["11:Example Browser:120.0.1:CVE-2000-0002"]
        self.assertEqual("High", finding.severity)
        self.assertEqual(7.5, finding.cvssv3_score)
        self.assertIn("**CVSS:** 7.5", finding.description)

    def test_a_host_id_may_be_a_string(self):
        findings = self.parse_string({"hosts": [{"id": "42", "hostname": "h.example.com", "software": [
            {"name": "pkg", "version": "1.0", "vulnerabilities": [{"cve": "CVE-2000-0001"}]},
        ]}]})
        self.assertEqual("42:pkg:1.0:CVE-2000-0001", findings[0].unique_id_from_tool)

    def test_cisa_known_exploited_is_called_out(self):
        """
        A CVE on CISA's list is flagged in the description and tagged.

        The connector does not raise the severity for it - the CVSS score still decides - so neither
        does this parser; the flag is what makes it findable.
        """
        findings = self.by_uid("fleet_vulnerabilities_many_vuln.json")
        flagged = findings["11:Example Browser:120.0.1:CVE-2000-0001"]
        self.assertIn("cisa-known-exploited", flagged.unsaved_tags)
        self.assertIn("CISA's Known Exploited Vulnerabilities list", flagged.description)

        not_flagged = findings["11:Example Browser:120.0.1:CVE-2000-0002"]
        self.assertNotIn("cisa-known-exploited", not_flagged.unsaved_tags)
        self.assertNotIn("CISA", not_flagged.description)

    def test_mitigation_without_a_fixed_version(self):
        finding = self.by_uid("fleet_vulnerabilities_many_vuln.json")["11:Example Reader:9.1:CVE-2000-0003"]
        self.assertIn("following the vendor's security advisory", finding.mitigation)
        self.assertIn("Fleet did not report a fixed version", finding.mitigation)

    def test_publish_date_accepts_a_date_or_a_timestamp(self):
        findings = self.by_uid("fleet_vulnerabilities_many_vuln.json")
        self.assertEqual(
            datetime(2024, 5, 1, tzinfo=UTC).date(),
            findings["11:Example Browser:120.0.1:CVE-2000-0001"].publish_date,
        )
        self.assertEqual(
            datetime(2024, 4, 15, tzinfo=UTC).date(),
            findings["11:Example Browser:120.0.1:CVE-2000-0002"].publish_date,
        )
        self.assertIsNone(findings["11:Example Reader:9.1:CVE-2000-0003"].publish_date)

    def test_tags_are_sorted_and_deduplicated(self):
        """
        The connector sorts and deduplicates its tags, so a reimport does not look like a change.

        Worth asserting rather than assuming: an unordered tag list is a diff on every sync.
        """
        for finding in self.parse("fleet_vulnerabilities_many_vuln.json"):
            with self.subTest(uid=finding.unique_id_from_tool):
                self.assertEqual(sorted(set(finding.unsaved_tags)), finding.unsaved_tags)
                self.assertIn("vulnerability", finding.unsaved_tags)
                self.assertIn("endpoint", finding.unsaved_tags)

    def test_host_name_falls_back_through_fleets_three_names(self):
        cases = (
            ({"display_name": "display", "computer_name": "computer", "hostname": "host"}, "display"),
            ({"computer_name": "computer", "hostname": "host"}, "computer"),
            ({"hostname": "host"}, "host"),
            ({"primary_ip": "10.0.0.9"}, ""),
        )
        for host, expected in cases:
            with self.subTest(host=host):
                self.assertEqual(expected, FleetVulnerabilitiesParser().host_name(host))

    def test_a_host_with_no_name_falls_back_to_its_address(self):
        findings = self.parse_string({"hosts": [{"id": 1, "primary_ip": "10.0.0.9", "software": [
            {"name": "pkg", "version": "1.0", "vulnerabilities": [{"cve": "CVE-2000-0001"}]},
        ]}]})
        self.assertEqual("CVE-2000-0001 - pkg 1.0", findings[0].title)
        self.assertEqual("10.0.0.9", self.get_unsaved_locations(findings[0])[0].host)

    def test_a_host_with_no_name_or_address_records_no_endpoint(self):
        findings = self.parse_string({"hosts": [{"id": 1, "software": [
            {"name": "pkg", "version": "1.0", "vulnerabilities": [{"cve": "CVE-2000-0001"}]},
        ]}]})
        self.assertEqual(0, len(self.get_unsaved_locations(findings[0])))

    def test_a_host_name_that_cannot_be_a_host_records_no_endpoint(self):
        """
        Fleet's display name is free text - "Jane's MacBook" is a normal value.

        DefectDojo's host field would reject it, and a ValidationError fails the whole import rather
        than the one finding, so the endpoint is dropped instead. The name is still in the
        description's Host line.
        """
        findings = self.parse_string({"hosts": [{
            "id": 1, "display_name": "Someone's MacBook Pro", "software": [
                {"name": "pkg", "version": "1.0", "vulnerabilities": [{"cve": "CVE-2000-0001"}]},
            ],
        }]})
        self.assertEqual([], self.get_unsaved_locations(findings[0]))
        self.assertIn("**Host:** Someone's MacBook Pro", findings[0].description)

    def test_an_ipv6_address_is_accepted_as_a_host(self):
        findings = self.parse_string({"hosts": [{
            "id": 1, "primary_ip": "2001:db8::1", "software": [
                {"name": "pkg", "version": "1.0", "vulnerabilities": [{"cve": "CVE-2000-0001"}]},
            ],
        }]})
        self.assertEqual("2001:db8::1", self.get_unsaved_locations(findings[0])[0].host)

    def test_single_host_and_bare_list_shapes(self):
        """Fleet's list response nests hosts under "hosts" and its single-host response under "host"."""
        host = {"id": 1, "hostname": "h.example.com", "software": [
            {"name": "pkg", "version": "1.0", "vulnerabilities": [{"cve": "CVE-2000-0001"}]},
        ]}
        for payload in ({"hosts": [host]}, {"host": host}, [host], host):
            with self.subTest(shape=next(iter(payload)) if isinstance(payload, dict) else "list"):
                findings = self.parse_string(payload)
                self.assertEqual(1, len(findings))
                self.assertEqual("CVE-2000-0001 - pkg 1.0 on h.example.com", findings[0].title)

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("Fleet", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("host", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"hosts": [
            "not an object",
            None,
            {"id": 1, "hostname": "h.example.com", "software": [
                "not an object",
                {"name": "pkg", "version": "1.0", "vulnerabilities": ["not an object", {"cve": "CVE-2000-0001"}]},
            ]},
        ]})
        self.assertEqual(1, len(findings))

    def test_a_host_with_no_software_is_not_an_error(self):
        self.assertEqual(0, len(self.parse_string({"hosts": [{"id": 1, "hostname": "h.example.com"}]})))

    def test_severity_is_always_a_known_value(self):
        for filename in ("fleet_vulnerabilities_many_vuln.json", "fleet_vulnerabilities_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
