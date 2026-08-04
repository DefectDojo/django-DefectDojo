import io
import json
from datetime import UTC, datetime

from dojo.models import Finding, Test
from dojo.tools.vanta.parser import VantaParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestVantaParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("vanta") / filename).open(encoding="utf-8") as file:
            return list(VantaParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(VantaParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Vanta connector's ScanTypeName verbatim.

        Note it does NOT follow the "<Vendor> - Connectors Import" pattern the other connector scan
        types use, so it cannot be derived - it has to be copied.
        """
        parser = VantaParser()
        self.assertEqual(["Vanta Compliance"], parser.get_scan_types())
        self.assertEqual("Vanta Compliance", parser.get_label_for_scan_types("Vanta Compliance"))
        self.assertNotIn("Vanta - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        """
        A test with no failing entity is the control working.

        Vanta has no finding of its own to import in that case - the pair is what makes a finding.
        """
        self.assertEqual(0, len(self.parse("vanta_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("vanta_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's finding_converter."""
        findings = self.parse("vanta_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("MFA is enabled for all users", finding.title)
        self.assertEqual("Medium", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("vanta-test-mfa-enabled-user-0001", finding.unique_id_from_tool)
        self.assertEqual("test-mfa-enabled", finding.vuln_id_from_tool)
        self.assertEqual("example-user@example.com", finding.component_name)
        self.assertEqual("Register an MFA device for each user listed below.", finding.mitigation)
        self.assertEqual(datetime(2024, 7, 1, tzinfo=UTC).date(), finding.date)
        self.assertTrue(finding.active)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(["compliance", "Access Control", "aws", "okta", "IAM_USER"], finding.unsaved_tags)

        self.assertEqual(
            "**Failing resource:** example-user@example.com\n"
            "**Resource type:** IAM_USER\n"
            "**Category:** Access Control\n"
            "**Integrations:** aws, okta\n\n"
            "**Description:**\n"
            "Every user with console access must have multi-factor authentication enabled.\n\n"
            "**Why this failed:**\n"
            "One or more users have no MFA device registered.",
            finding.description,
        )

    def test_every_finding_is_medium(self):
        """
        Vanta has no severity scale - a compliance test passes or fails.

        The connector grades every failing entity Medium rather than inventing a ladder, and Info
        would read as non-actionable when a failing control is actionable by definition.
        """
        severities = {finding.severity for finding in self.parse("vanta_many_vuln.json")}
        self.assertEqual({"Medium"}, severities)

    def test_many_vuln(self):
        """One finding per failing entity: four across three tests, and one passing entity skipped."""
        self.assertEqual(4, len(self.parse("vanta_many_vuln.json")))

    def test_one_control_failing_on_two_resources_is_two_findings(self):
        """
        The resource is half the identity, and the component keeps them apart in the hash.

        That matters more here than usual: every Vanta finding shares the same severity, so without
        the component two resources failing one control would merge.
        """
        findings = self.by_uid("vanta_many_vuln.json")
        self.assertIn("vanta-test-mfa-enabled-user-0001", findings)
        self.assertIn("vanta-test-mfa-enabled-user-0002", findings)
        self.assertEqual("example-user@example.com", findings["vanta-test-mfa-enabled-user-0001"].component_name)
        self.assertEqual("second-user@example.com", findings["vanta-test-mfa-enabled-user-0002"].component_name)
        # Both point at the same control.
        self.assertEqual("test-mfa-enabled", findings["vanta-test-mfa-enabled-user-0001"].vuln_id_from_tool)
        self.assertEqual("test-mfa-enabled", findings["vanta-test-mfa-enabled-user-0002"].vuln_id_from_tool)

    def test_a_passing_entity_is_not_a_finding(self):
        """
        The connector asks Vanta for the FAILING entities specifically.

        An export that carries every entity is filtered here instead, so a compliant resource does not
        arrive as a finding.
        """
        findings = self.by_uid("vanta_many_vuln.json")
        self.assertNotIn("vanta-test-mfa-enabled-user-0003", findings)

    def test_an_entity_with_no_status_is_treated_as_failing(self):
        """
        The connector only ever receives failing entities, so it does not check the status.

        An export listing entities without one is therefore taken at its word rather than dropped.
        """
        findings = self.parse_string({
            "results": {"data": [{"id": "t1", "name": "A control"}]},
            "entities": {"t1": [{"id": "e1", "displayName": "a-resource"}]},
        })
        self.assertEqual(1, len(findings))

    def test_a_test_with_no_failing_entities_produces_nothing(self):
        titles = {finding.title for finding in self.parse("vanta_many_vuln.json")}
        self.assertNotIn("Backups are configured", titles)

    def test_failing_entities_may_be_nested_or_keyed_by_test_id(self):
        """
        Vanta needs a call per test to learn what is failing, and those rows carry no test id.

        So an export either nests them or keys them by test id, and both the paged
        results.data wrapper and a bare list have to work.
        """
        findings = self.by_uid("vanta_many_vuln.json")
        # test-mfa-enabled uses the paged wrapper; test-disk-encryption uses a bare list.
        self.assertIn("vanta-test-mfa-enabled-user-0001", findings)
        self.assertIn("vanta-test-disk-encryption-workstation-0001", findings)

        nested = self.parse_string({"results": {"data": [
            {"id": "t1", "name": "A control", "entities": [{"id": "e1", "displayName": "a-resource"}]},
        ]}})
        self.assertEqual("vanta-t1-e1", nested[0].unique_id_from_tool)

    def test_title_falls_back_to_the_test_id(self):
        finding = self.by_uid("vanta_many_vuln.json")["vanta-test-unnamed-resource-0001"]
        self.assertEqual("Vanta test test-unnamed", finding.title)

    def test_the_entity_date_wins_over_the_tests_flip_date(self):
        """
        One control can have been failing for a year while a resource added last week has only just
        started failing it, so the entity's own date is preferred.
        """
        findings = self.by_uid("vanta_many_vuln.json")
        self.assertEqual(
            datetime(2024, 7, 1, tzinfo=UTC).date(),
            findings["vanta-test-mfa-enabled-user-0001"].date,
        )
        # No entity date here, so the test's flip date stands in.
        self.assertEqual(
            datetime(2024, 5, 1, tzinfo=UTC).date(),
            findings["vanta-test-disk-encryption-workstation-0001"].date,
        )

    def test_an_unparseable_entity_date_falls_back_to_the_flip_date(self):
        findings = self.by_uid("vanta_many_vuln.json")
        self.assertEqual(
            datetime(2024, 6, 20, tzinfo=UTC).date(),
            findings["vanta-test-mfa-enabled-user-0002"].date,
        )

    def test_no_date_at_all_keeps_the_default(self):
        finding = self.by_uid("vanta_many_vuln.json")["vanta-test-unnamed-resource-0001"]
        self.assertEqual(datetime.now(tz=UTC).date(), finding.date)

    def test_a_test_with_no_integrations_has_no_integrations_line(self):
        finding = self.by_uid("vanta_many_vuln.json")["vanta-test-disk-encryption-workstation-0001"]
        self.assertNotIn("**Integrations:**", finding.description)
        self.assertEqual(["compliance", "Endpoint Security", "WORKSTATION"], finding.unsaved_tags)

    def test_a_bare_list_of_tests_is_accepted(self):
        findings = self.parse_string([
            {"id": "t1", "name": "A control", "entities": [{"id": "e1", "displayName": "a-resource"}]},
        ])
        self.assertEqual(1, len(findings))

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("Vanta", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("results.data", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"results": {"data": [
            "not an object",
            None,
            {"id": "t1", "name": "A control",
             "entities": ["not an object", {"id": "e1", "displayName": "a-resource"}]},
        ]}})
        self.assertEqual(1, len(findings))

    def test_severity_is_always_a_known_value(self):
        for filename in ("vanta_many_vuln.json", "vanta_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
