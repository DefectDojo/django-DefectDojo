import io
import json

from dojo.models import Finding, Test
from dojo.tools.fleet_policies.parser import FleetPoliciesParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestFleetPoliciesParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("fleet_policies") / filename
        with path.open(encoding="utf-8") as file:
            return list(FleetPoliciesParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(FleetPoliciesParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Fleet connector's ScanTypePolicies verbatim.

        Any drift and a customer who uploads an export and also syncs the API gets two
        un-deduplicated copies of every failing policy.
        """
        parser = FleetPoliciesParser()
        self.assertEqual(["Fleet:Policies - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "Fleet:Policies - Connectors Import",
            parser.get_label_for_scan_types("Fleet:Policies - Connectors Import"),
        )
        self.assertNotIn("Fleet:Vulnerabilities - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        """
        Policies that all pass produce nothing.

        The sample also carries a software CVE, which this parser must ignore: vulnerabilities are a
        separate scan type with their own deduplication key.
        """
        self.assertEqual(0, len(self.parse("fleet_policies_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("fleet_policies_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring policyFinding in the connector's converter."""
        findings = self.parse("fleet_policies_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Disk encryption enabled", finding.title)
        # Fleet marks this policy critical.
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("11:policy:90", finding.unique_id_from_tool)
        self.assertEqual("fleet-policy-90", finding.vuln_id_from_tool)
        self.assertEqual("Turn on FileVault in System Settings, Privacy & Security.", finding.mitigation)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(["compliance", "critical-policy", "darwin", "endpoint", "policy"], finding.unsaved_tags)

        sections = finding.description.split("\n\n")
        self.assertEqual("Checks that FileVault is enabled on the startup volume.", sections[0])
        self.assertEqual("This Fleet policy is **failing** on this host.", sections[1])
        self.assertEqual("**Host:** laptop-11 (10.0.0.11)", sections[2])
        self.assertEqual("**OS:** darwin macOS 14.5", sections[3])
        self.assertEqual("**Policy query**", sections[4])
        self.assertIn("```sql", finding.description)
        self.assertIn("SELECT 1 FROM disk_encryption", finding.description)

        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("laptop-11", locations[0].host)

    def test_many_vuln(self):
        """Two failing policies on one host and one on another; the rest are skipped."""
        self.assertEqual(3, len(self.parse("fleet_policies_many_vuln.json")))

    def test_only_failing_policies_are_imported(self):
        """
        Fleet reports every policy's outcome per host, not just the failures.

        A passing policy is not a finding, and neither is one Fleet has no result for - an empty
        response means the query has not run on that host yet.
        """
        findings = self.by_uid("fleet_policies_many_vuln.json")
        self.assertIn("11:policy:90", findings)
        self.assertIn("11:policy:91", findings)
        # 92 passes, 93 has no name, 94 has no result yet.
        self.assertNotIn("11:policy:92", findings)
        self.assertNotIn("11:policy:93", findings)
        self.assertNotIn("11:policy:94", findings)

    def test_response_is_read_case_insensitively(self):
        """The second host reports the same policy as "FAIL"."""
        self.assertIn("12:policy:90", self.by_uid("fleet_policies_many_vuln.json"))

    def test_a_critical_policy_is_high_and_the_rest_are_medium(self):
        findings = self.by_uid("fleet_policies_many_vuln.json")
        self.assertEqual("High", findings["11:policy:90"].severity)
        self.assertEqual("Medium", findings["11:policy:91"].severity)
        self.assertIn("critical-policy", findings["11:policy:90"].unsaved_tags)
        self.assertNotIn("critical-policy", findings["11:policy:91"].unsaved_tags)

    def test_the_same_policy_on_two_hosts_is_two_findings(self):
        """
        A policy failing on two machines is two findings.

        The host is part of the identity because remediating one machine does not fix the other.
        """
        findings = [
            finding for finding in self.parse("fleet_policies_many_vuln.json")
            if finding.title == "Disk encryption enabled"
        ]
        self.assertEqual(2, len(findings))
        self.assertEqual({"11:policy:90", "12:policy:90"}, {f.unique_id_from_tool for f in findings})
        # Both point at the same policy, which is what the deduplication hash keys on.
        self.assertEqual({"fleet-policy-90"}, {f.vuln_id_from_tool for f in findings})

    def test_the_platform_of_both_the_policy_and_the_host_is_tagged(self):
        findings = self.by_uid("fleet_policies_many_vuln.json")
        self.assertEqual(
            ["compliance", "critical-policy", "endpoint", "linux", "policy", "ubuntu"],
            findings["12:policy:90"].unsaved_tags,
        )

    def test_tags_are_sorted_and_deduplicated(self):
        """
        The connector sorts and deduplicates its tags, so a reimport does not look like a change.

        On the first host the policy platform and the host platform are both "darwin", which is
        exactly the case the deduplication is for.
        """
        for finding in self.parse("fleet_policies_many_vuln.json"):
            with self.subTest(uid=finding.unique_id_from_tool):
                self.assertEqual(sorted(set(finding.unsaved_tags)), finding.unsaved_tags)
        self.assertEqual(
            ["compliance", "critical-policy", "darwin", "endpoint", "policy"],
            self.by_uid("fleet_policies_many_vuln.json")["11:policy:90"].unsaved_tags,
        )

    def test_a_policy_without_a_description_or_query(self):
        findings = self.parse_string({"hosts": [{"id": 1, "hostname": "h.example.com", "policies": [
            {"id": 5, "name": "Bare policy", "response": "fail"},
        ]}]})
        self.assertEqual(
            "This Fleet policy is **failing** on this host.\n\n**Host:** h.example.com",
            findings[0].description,
        )
        self.assertEqual("", findings[0].mitigation)

    def test_ids_may_be_strings(self):
        findings = self.parse_string({"hosts": [{"id": "42", "hostname": "h.example.com", "policies": [
            {"id": "7", "name": "String ids", "response": "fail"},
        ]}]})
        self.assertEqual("42:policy:7", findings[0].unique_id_from_tool)
        self.assertEqual("fleet-policy-7", findings[0].vuln_id_from_tool)

    def test_single_host_and_bare_list_shapes(self):
        host = {"id": 1, "hostname": "h.example.com", "policies": [
            {"id": 5, "name": "A policy", "response": "fail"},
        ]}
        for payload in ({"hosts": [host]}, {"host": host}, [host], host):
            with self.subTest(shape=next(iter(payload)) if isinstance(payload, dict) else "list"):
                findings = self.parse_string(payload)
                self.assertEqual(1, len(findings))
                self.assertEqual("A policy", findings[0].title)

    def test_a_host_with_no_name_falls_back_to_its_address(self):
        findings = self.parse_string({"hosts": [{"id": 1, "primary_ip": "10.0.0.9", "policies": [
            {"id": 5, "name": "A policy", "response": "fail"},
        ]}]})
        self.assertEqual("10.0.0.9", self.get_unsaved_locations(findings[0])[0].host)

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
            {"id": 1, "hostname": "h.example.com", "policies": [
                "not an object",
                {"id": 5, "name": "A policy", "response": "fail"},
            ]},
        ]})
        self.assertEqual(1, len(findings))

    def test_a_host_with_no_policies_is_not_an_error(self):
        self.assertEqual(0, len(self.parse_string({"hosts": [{"id": 1, "hostname": "h.example.com"}]})))
