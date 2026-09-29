import io
import json
from datetime import UTC, date, datetime

from dojo.models import Finding, Test
from dojo.tools.codacy.parser import CodacyParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestCodacyParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("codacy") / filename).open(encoding="utf-8") as file:
            return list(CodacyParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(CodacyParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def by_uid(self, filename):
        return {f.unique_id_from_tool: f for f in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Codacy connector's ScanType() verbatim.

        Any drift and a customer who uploads an export and also syncs the API gets two
        un-deduplicated copies of every finding.
        """
        parser = CodacyParser()
        self.assertEqual(["Codacy - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "Codacy - Connectors Import",
            parser.get_label_for_scan_types("Codacy - Connectors Import"),
        )

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("codacy_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("codacy_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring ItemToFinding in the connector's converter."""
        findings = self.parse("codacy_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("CVE-2000-0001 in generic-lib", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("00000000-0000-4000-8000-000000000001", finding.unique_id_from_tool)
        self.assertEqual("CVE-2000-0001", finding.vuln_id_from_tool)
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual(502, finding.cwe)
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", finding.cvssv3)
        self.assertEqual("https://app.example.com/items/1", finding.references)
        self.assertEqual(date(2026, 6, 10), finding.date)
        self.assertTrue(finding.active)
        self.assertFalse(finding.false_p)

    def test_the_component_is_the_last_entry_of_the_dependency_chain(self):
        """
        The vulnerable package is the deepest entry, not the project at the head of the chain.

        Taking the first entry would name the application as the vulnerable component on every SCA
        finding.
        """
        finding = self.parse("codacy_one_vuln.json")[0]
        self.assertEqual("generic-lib", finding.component_name)
        self.assertEqual("1.2.3", finding.component_version)
        self.assertIn(
            "**Dependency path:** generic-app → generic-framework → generic-lib",
            finding.description,
        )

    def test_the_first_non_empty_chain_is_used(self):
        """A leading empty chain must not make the parser conclude there is no package."""
        finding = self.by_uid("codacy_many_vuln.json")["00000000-0000-4000-8000-000000000003"]
        self.assertEqual("generic-openssl", finding.component_name)

    def test_a_dast_item_is_dynamic_and_everything_else_is_static(self):
        """
        Codacy reports SCA, container and DAST items through one endpoint.

        Only DAST looked at something running, so flagging every item static - or every item dynamic -
        would misreport most of them.
        """
        findings = self.by_uid("codacy_many_vuln.json")
        sca = findings["00000000-0000-4000-8000-000000000001"]
        self.assertTrue(sca.static_finding)
        self.assertFalse(sca.dynamic_finding)

        dast = findings["00000000-0000-4000-8000-000000000002"]
        self.assertFalse(dast.static_finding)
        self.assertTrue(dast.dynamic_finding)

        container = findings["00000000-0000-4000-8000-000000000003"]
        self.assertTrue(container.static_finding)
        self.assertFalse(container.dynamic_finding)

    def test_the_scanned_target_is_recorded(self):
        """
        A DAST item names the application it scanned; a container item names the image.

        Asserted through get_unsaved_locations so this passes with V3_FEATURE_LOCATIONS either way.
        """
        findings = self.by_uid("codacy_many_vuln.json")
        dast = self.get_unsaved_locations(findings["00000000-0000-4000-8000-000000000002"])
        self.assertEqual(1, len(dast))
        self.assertEqual("app.example.com", dast[0].host)

        # No application, so the converter falls back to affectedTargets - an image reference, whose
        # repository is a path rather than part of the host. Leaving it in the host field fails
        # Endpoint.clean(), and that fails the whole import rather than this one finding.
        container = self.get_unsaved_locations(findings["00000000-0000-4000-8000-000000000003"])
        self.assertEqual(1, len(container))
        self.assertEqual("registry.example.com", container[0].host)
        self.assertEqual("generic-app", container[0].path)

    def test_a_target_that_cannot_be_a_host_records_no_endpoint(self):
        """
        DefectDojo's host field accepts letters, digits, dot, hyphen, underscore, plus, or an IP.

        An image reference with a tag has nowhere sensible to go - the tag is neither a port nor part
        of a path - so no endpoint is recorded rather than one that fails validation and takes the
        whole import down with it. The value is still in the description.
        """
        findings = self.parse_string({"items": [
            {"itemId": "1", "affectedTargets": "generic-app:1.2", "priority": "high"},
        ]})
        self.assertEqual([], self.get_unsaved_locations(findings[0]))

    def test_an_application_url_is_split_into_its_parts(self):
        findings = self.parse_string({"items": [
            {"itemId": "1", "application": "https://app.example.com:8443/login", "priority": "high"},
        ]})
        location = self.get_unsaved_locations(findings[0])[0]
        self.assertEqual("app.example.com", location.host)
        self.assertEqual(8443, location.port)
        self.assertEqual("https", location.protocol)
        self.assertEqual("login", location.path)

    def test_an_item_with_no_target_records_none(self):
        finding = self.by_uid("codacy_many_vuln.json")["00000000-0000-4000-8000-000000000001"]
        self.assertEqual([], self.get_unsaved_locations(finding))

    def test_an_item_ignored_as_a_false_positive_is_flagged(self):
        """
        Codacy can ignore an item, and the reason says whether a human judged it a false positive.

        The comparison strips spaces, so Codacy's "False Positive" matches. Importing it as an
        ordinary active finding would put triaged noise back in front of the team.
        """
        finding = self.by_uid("codacy_many_vuln.json")["00000000-0000-4000-8000-000000000003"]
        self.assertTrue(finding.false_p)

    def test_any_other_ignore_reason_is_not_a_false_positive(self):
        """"Acceptable risk" is a real finding somebody accepted, not a mistake."""
        finding = self.by_uid("codacy_many_vuln.json")["00000000-0000-4000-8000-000000000004"]
        self.assertFalse(finding.false_p)

    def test_the_false_positive_check_directly(self):
        parser = CodacyParser()
        for reason, expected in [
            ("falsepositive", True), ("False Positive", True), ("FALSE POSITIVE", True),
            ("Acceptable risk", False), ("", False),
        ]:
            self.assertEqual(expected, parser.is_false_positive({"ignored": {"reason": reason}}), reason)
        self.assertFalse(parser.is_false_positive({"ignored": None}))
        self.assertFalse(parser.is_false_positive({}))

    def test_several_cves_in_one_field_are_all_imported_and_deduplicated(self):
        """
        Codacy's "cve" is a typed string documented as possibly holding several identifiers.

        Reading it as a single value would drop the rest; the fixture repeats one to prove the
        deduplication.
        """
        finding = self.by_uid("codacy_many_vuln.json")["00000000-0000-4000-8000-000000000003"]
        self.assertEqual(["CVE-2000-0003", "CVE-2000-0004"], finding.unsaved_vulnerability_ids)
        # vuln_id_from_tool takes the first CVE found.
        self.assertEqual("CVE-2000-0003", finding.vuln_id_from_tool)

    def test_an_item_with_no_cve_falls_back_to_the_codacy_source_id(self):
        finding = self.by_uid("codacy_many_vuln.json")["00000000-0000-4000-8000-000000000002"]
        self.assertEqual("ZAP-40012", finding.vuln_id_from_tool)
        self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_an_item_with_no_title_is_named_from_the_scan_type_and_category(self):
        finding = self.by_uid("codacy_many_vuln.json")["00000000-0000-4000-8000-000000000002"]
        self.assertEqual("Codacy DAST - Injection item", finding.title)

    def test_an_item_with_neither_title_nor_scan_type_names_the_item_id(self):
        finding = self.by_uid("codacy_many_vuln.json")["00000000-0000-4000-8000-000000000004"]
        self.assertEqual(
            "Codacy security item 00000000-0000-4000-8000-000000000004", finding.title,
        )

    def test_an_unparseable_cwe_leaves_the_cwe_at_zero(self):
        finding = self.by_uid("codacy_many_vuln.json")["00000000-0000-4000-8000-000000000003"]
        self.assertEqual(0, finding.cwe)

    def test_an_unrecognised_priority_is_info(self):
        finding = self.by_uid("codacy_many_vuln.json")["00000000-0000-4000-8000-000000000004"]
        self.assertEqual("Info", finding.severity)

    def test_an_unparseable_timestamp_dates_the_finding_today(self):
        """
        The converter falls back to now() so that a finding always carries a date.

        Mirrored rather than corrected; asserted as a range so the test cannot flake on a date
        rollover between the parse and the assertion.
        """
        finding = self.by_uid("codacy_many_vuln.json")["00000000-0000-4000-8000-000000000004"]
        self.assertIsNotNone(finding.date)
        today = datetime.now(tz=UTC).date()
        self.assertLessEqual(abs((finding.date - today).days), 1)

    def test_the_container_image_is_reported_with_its_tag(self):
        finding = self.by_uid("codacy_many_vuln.json")["00000000-0000-4000-8000-000000000003"]
        self.assertIn(
            "**Container image:** registry.example.com/generic-app:1.4.0", finding.description,
        )

    def test_an_image_with_no_tag_is_reported_bare(self):
        parser = CodacyParser()
        self.assertEqual("generic-app", parser.container_image({"imageName": "generic-app"}))
        self.assertEqual("", parser.container_image({"imageName": "", "imageTag": "1.0"}))

    def test_mitigation_carries_the_remediation_and_the_fixed_versions(self):
        finding = self.parse("codacy_one_vuln.json")[0]
        self.assertEqual(
            "Upgrade generic-lib to 1.2.4 or later.\n\nFixed in: 1.2.4, 2.0.0",
            finding.mitigation,
        )

    def test_an_item_with_neither_remediation_nor_fixed_versions_has_no_mitigation(self):
        finding = self.by_uid("codacy_many_vuln.json")["00000000-0000-4000-8000-000000000004"]
        self.assertIsNone(finding.mitigation)

    def test_tags_mirror_the_converter(self):
        finding = self.parse("codacy_one_vuln.json")[0]
        self.assertEqual(["SCA", "Vulnerability", "Trivy"], finding.unsaved_tags)

    def test_the_description_carries_the_detector_and_repository(self):
        finding = self.parse("codacy_one_vuln.json")[0]
        self.assertIn("generic-lib is vulnerable to remote code execution.", finding.description)
        self.assertIn("The library evaluates untrusted input", finding.description)
        self.assertIn("**Detected by:** Trivy", finding.description)
        self.assertIn("**Repository:** generic-app", finding.description)
        self.assertIn("**Likelihood:** High", finding.description)
        self.assertIn("**Effort to fix:** Low", finding.description)

    def test_a_bare_array_is_accepted(self):
        report = io.StringIO(json.dumps([{"id": "i1", "priority": "Low", "title": "An item"}]))
        self.assertEqual(1, len(list(CodacyParser().get_findings(report, Test()))))

    def test_a_repeated_item_id_collapses(self):
        item = {"id": "same", "priority": "Low", "title": "An item"}
        report = io.StringIO(json.dumps({"data": [item, item]}))
        self.assertEqual(1, len(list(CodacyParser().get_findings(report, Test()))))

    def test_an_unexpected_shape_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(CodacyParser().get_findings(io.StringIO('"nope"'), Test()))
        self.assertIn("data", str(raised.exception))
