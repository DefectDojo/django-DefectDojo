import io
import json

from dojo.models import Finding, Test
from dojo.tools.action1.parser import Action1Parser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestAction1Parser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("action1") / filename).open(encoding="utf-8") as file:
            return list(Action1Parser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(Action1Parser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Action1 connector's ScanTypeName verbatim.

        Note it does NOT follow the "<Vendor> - Connectors Import" pattern the other connector scan
        types use, so it cannot be derived - it has to be copied. Any drift and someone who uploads
        an export and also syncs the API gets two un-deduplicated copies of every finding.
        """
        parser = Action1Parser()
        self.assertEqual(["Action1 Scan"], parser.get_scan_types())
        self.assertEqual("Action1 Scan", parser.get_label_for_scan_types("Action1 Scan"))
        self.assertNotIn("Action1 - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("action1_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("action1_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's finding_converter."""
        findings = self.parse("action1_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Remote code execution in Example Browser", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertEqual("action1-CVE-2000-0001-ep-0001", finding.unique_id_from_tool)
        self.assertEqual("CVE-2000-0001", finding.vuln_id_from_tool)
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual("Example Browser", finding.component_name)
        # The endpoint's own copy of the software, not the vulnerability's.
        self.assertEqual("119.0.4", finding.component_version)
        self.assertEqual("Apply: Example Browser 120.0.2", finding.mitigation)
        self.assertTrue(finding.active)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

        self.assertEqual(
            "**CVE:** CVE-2000-0001\n"
            "**Endpoint:** workstation-01\n"
            "**OS:** Windows 11 Pro 23H2\n"
            "**Remediation status:** Overdue",
            finding.description,
        )

        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("workstation-01", locations[0].host)

    def test_the_description_uses_single_newlines(self):
        """
        The connector joins these lines with one newline, not a blank line.

        Mirrored rather than tidied: a gratuitous difference between the two import paths is still a
        difference.
        """
        finding = self.parse("action1_one_vuln.json")[0]
        self.assertNotIn("\n\n", finding.description)

    def test_many_vuln(self):
        """One finding per vulnerability per affected endpoint."""
        self.assertEqual(4, len(self.parse("action1_many_vuln.json")))

    def test_one_cve_on_two_machines_is_two_findings(self):
        """
        The endpoint is half of the identity, because the installed version differs per machine.

        Collapsing them would hide a machine that is still running the vulnerable build - which is
        also why the component version is part of this scan type's deduplication hash.
        """
        findings = self.by_uid("action1_many_vuln.json")
        self.assertIn("action1-CVE-2000-0001-ep-0001", findings)
        self.assertIn("action1-CVE-2000-0001-ep-0002", findings)
        self.assertEqual("119.0.4", findings["action1-CVE-2000-0001-ep-0001"].component_version)
        self.assertEqual("120.0.1", findings["action1-CVE-2000-0001-ep-0002"].component_version)

    def test_a_vulnerability_with_no_affected_endpoint_produces_nothing(self):
        """
        Action1 reports a vulnerability catalogue separately from what is actually affected.

        The connector only writes a finding per affected endpoint, so a catalogue entry nothing is
        running is not imported.
        """
        findings = self.by_uid("action1_many_vuln.json")
        self.assertFalse([uid for uid in findings if "CVE-2000-0004" in uid])

    def test_an_affected_endpoint_row_with_no_id_is_skipped(self):
        """The id is half the identity, so a row without one cannot be reported."""
        findings = self.by_uid("action1_many_vuln.json")
        self.assertNotIn("action1-CVE-2000-0001-", findings)

    def test_severity_prefers_base_severity_then_the_score_bucket(self):
        """
        Action1's "score" is a WORD, not a number - Critical/High/Medium/Low.

        Treating it as numeric would drop every finding whose base severity is missing to Info.
        """
        findings = self.by_uid("action1_many_vuln.json")
        self.assertEqual("Medium", findings["action1-CVE-2000-0002-ep-0001"].severity)

        for base, score, expected in (("Critical", "", "Critical"), ("High", "Low", "High"),
                                      ("", "Medium", "Medium"), ("", "Low", "Low"),
                                      ("Not graded", "High", "Info"), ("", "", "Info")):
            with self.subTest(base=base, score=score):
                parsed = self.parse_string({
                    "items": [{"cve_id": "CVE-2000-0001", "base_severity": base, "score": score,
                               "endpoints": [{"endpoint_id": "ep-1"}]}],
                })
                self.assertEqual(expected, parsed[0].severity)

    def test_an_unrecognised_bucket_is_info(self):
        finding = self.by_uid("action1_many_vuln.json")["action1-CVE-2000-0003-ep-0003"]
        self.assertEqual("Info", finding.severity)

    def test_title_falls_back_to_the_cve_then_to_a_constant(self):
        findings = self.by_uid("action1_many_vuln.json")
        self.assertEqual("CVE-2000-0003", findings["action1-CVE-2000-0003-ep-0003"].title)

        parsed = self.parse_string({"items": [{"endpoints": [{"endpoint_id": "ep-1"}]}]})
        self.assertEqual("Action1 vulnerability", parsed[0].title)
        self.assertIsNone(parsed[0].vuln_id_from_tool)

    def test_an_unscored_vulnerability_lands_as_zero(self):
        """
        The connector sets the CVSS score unconditionally, so an unscored vulnerability gets 0.0.

        Mirrored for parity rather than left unset; flagged in the PR as a follow-up for both sides.
        """
        finding = self.by_uid("action1_many_vuln.json")["action1-CVE-2000-0003-ep-0003"]
        self.assertEqual(0.0, finding.cvssv3_score)

    def test_a_score_may_arrive_as_a_string(self):
        finding = self.by_uid("action1_many_vuln.json")["action1-CVE-2000-0002-ep-0001"]
        self.assertEqual(6.5, finding.cvssv3_score)

    def test_mitigation_lists_every_available_update(self):
        finding = self.by_uid("action1_many_vuln.json")["action1-CVE-2000-0001-ep-0001"]
        self.assertEqual(
            "Apply: Example Browser 120.0.2, Example Browser security update",
            finding.mitigation,
        )

    def test_no_available_updates_leaves_the_mitigation_empty(self):
        """
        Action1 knows of no patch, and the connector says nothing rather than inventing advice.

        Writing "update the software" here would be this parser's opinion, not Action1's.
        """
        findings = self.by_uid("action1_many_vuln.json")
        self.assertEqual("", findings["action1-CVE-2000-0001-ep-0002"].mitigation)
        self.assertEqual("", findings["action1-CVE-2000-0002-ep-0001"].mitigation)

    def test_software_falls_back_to_the_vulnerabilitys_own_copy(self):
        """The endpoint's copy is preferred; the vulnerability's is the fallback."""
        finding = self.by_uid("action1_many_vuln.json")["action1-CVE-2000-0002-ep-0001"]
        self.assertEqual("Example Reader", finding.component_name)
        self.assertEqual("9.1", finding.component_version)

    def test_a_vulnerability_with_no_software_has_no_component(self):
        finding = self.by_uid("action1_many_vuln.json")["action1-CVE-2000-0003-ep-0003"]
        self.assertIsNone(finding.component_name)
        self.assertIsNone(finding.component_version)

    def test_the_endpoint_name_falls_back_to_its_id(self):
        findings = self.parse_string({"items": [
            {"cve_id": "CVE-2000-0001", "endpoints": [{"endpoint_id": "ep-0009"}]},
        ]})
        self.assertIn("**Endpoint:** ep-0009", findings[0].description)

    def test_a_machine_name_that_cannot_be_a_host_is_not_recorded(self):
        """
        An Action1 endpoint name is free text - "Reception Desk PC" is a normal value.

        DefectDojo's host field would reject it, and a ValidationError fails the whole import rather
        than the one finding, so the endpoint is dropped. The name is still in the description.
        """
        finding = self.by_uid("action1_many_vuln.json")["action1-CVE-2000-0003-ep-0003"]
        self.assertEqual([], self.get_unsaved_locations(finding))
        self.assertIn("**Endpoint:** Reception Desk PC", finding.description)

    def test_affected_endpoints_may_be_nested_or_keyed_by_cve(self):
        """
        Action1 needs a call per CVE to learn what is affected, and those rows carry no CVE of their
        own, so an export either nests them or keys them by CVE id. Both have to work.
        """
        nested = self.parse("action1_one_vuln.json")[0]

        with (get_unit_tests_scans_path("action1") / "action1_one_vuln.json").open(encoding="utf-8") as file:
            export = json.load(file)
        vulnerability = export["items"][0]
        endpoints = vulnerability.pop("endpoints")
        keyed = self.parse_string({
            "items": [vulnerability],
            "endpoints": {vulnerability["cve_id"]: endpoints},
            "managed_endpoints": export["managed_endpoints"],
        })
        self.assertEqual(nested.unique_id_from_tool, keyed[0].unique_id_from_tool)
        self.assertEqual(nested.description, keyed[0].description)
        self.assertEqual(nested.component_version, keyed[0].component_version)

    def test_the_operating_system_is_best_effort(self):
        """A machine missing from the managed-endpoint list simply has no OS line."""
        findings = self.parse_string({
            "items": [{"cve_id": "CVE-2000-0001", "endpoints": [{"endpoint_id": "ep-1", "endpoint_name": "host-1"}]}],
        })
        self.assertNotIn("**OS:**", findings[0].description)
        self.assertIn("**Endpoint:** host-1", findings[0].description)

    def test_managed_endpoints_may_be_a_bare_list_or_a_paged_response(self):
        for managed in ([{"id": "ep-1", "OS": "Windows 11 Pro 23H2"}],
                        {"items": [{"id": "ep-1", "OS": "Windows 11 Pro 23H2"}]}):
            with self.subTest(shape=type(managed).__name__):
                findings = self.parse_string({
                    "items": [{"cve_id": "CVE-2000-0001", "endpoints": [{"endpoint_id": "ep-1"}]}],
                    "managed_endpoints": managed,
                })
                self.assertIn("**OS:** Windows 11 Pro 23H2", findings[0].description)

    def test_a_bare_list_of_vulnerabilities_is_accepted(self):
        findings = self.parse_string([
            {"cve_id": "CVE-2000-0001", "base_severity": "High", "endpoints": [{"endpoint_id": "ep-1"}]},
        ])
        self.assertEqual(1, len(findings))
        self.assertEqual("High", findings[0].severity)

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("Action1", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("items", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"items": [
            "not an object",
            None,
            {"cve_id": "CVE-2000-0001", "base_severity": "High",
             "endpoints": ["not an object", {"endpoint_id": "ep-1"}]},
        ]})
        self.assertEqual(1, len(findings))

    def test_severity_is_always_a_known_value(self):
        for filename in ("action1_many_vuln.json", "action1_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
