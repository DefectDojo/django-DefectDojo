import io
import json

from dojo.models import Finding, Test
from dojo.tools.fairwinds.parser import FairwindsParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestFairwindsParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("fairwinds") / filename).open(encoding="utf-8") as file:
            return list(FairwindsParser().get_findings(file, Test()))

    def by_uid(self, filename):
        return {f.unique_id_from_tool: f for f in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Fairwinds Insights connector's ScanType() verbatim.

        Any drift and a customer who uploads an export and also syncs the API gets two
        un-deduplicated copies of every finding.
        """
        parser = FairwindsParser()
        self.assertEqual(["Fairwinds Insights - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "Fairwinds Insights - Connectors Import",
            parser.get_label_for_scan_types("Fairwinds Insights - Connectors Import"),
        )

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("fairwinds_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("fairwinds_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring ActionItemToFinding in the connector's converter."""
        findings = self.parse("fairwinds_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("CVE-2000-0001 in openssl", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("5001", finding.unique_id_from_tool)
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual("Rebuild the image on a patched base.", finding.mitigation)
        self.assertTrue(finding.active)
        self.assertFalse(finding.is_mitigated)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

    def test_severity_is_a_float_score_not_a_word(self):
        """
        Fairwinds scores severity as a normalised 0.0-1.0 FLOAT.

        It is neither a severity word nor a CVSS score, so the breakpoints are Fairwinds' own:
        0.9 Critical, 0.7 High, 0.4 Medium, 0.1 Low, below that Info. Treating the number as CVSS
        would put every finding at Info.
        """
        parser = FairwindsParser()
        for score, expected in [
            (1.0, "Critical"), (0.9, "Critical"), (0.89, "High"), (0.7, "High"),
            (0.69, "Medium"), (0.4, "Medium"), (0.39, "Low"), (0.1, "Low"),
            (0.09, "Info"), (0.0, "Info"),
        ]:
            self.assertEqual(expected, parser.severity(score), score)

    def test_the_severity_ladder_against_the_fixture(self):
        findings = self.by_uid("fairwinds_many_vuln.json")
        self.assertEqual("Critical", findings["5001"].severity)  # 0.95
        self.assertEqual("High", findings["5002"].severity)      # 0.75
        self.assertEqual("Medium", findings["5003"].severity)    # 0.5
        self.assertEqual("Low", findings["5004"].severity)       # 0.2
        self.assertEqual("Info", findings["5005"].severity)      # 0.05

    def test_a_malformed_severity_is_info_rather_than_an_error(self):
        finding = self.by_uid("fairwinds_many_vuln.json")["5006"]
        self.assertEqual("Info", finding.severity)

    def test_a_fixed_item_is_imported_closed(self):
        """
        Fairwinds tracks whether an item has been fixed.

        Importing a fixed item as active would put resolved work back in the open queue.
        """
        finding = self.by_uid("fairwinds_many_vuln.json")["5003"]
        self.assertFalse(finding.active)
        self.assertTrue(finding.is_mitigated)

    def test_the_component_is_the_image_when_there_is_one(self):
        """
        Fairwinds aggregates several scanners, so an item may be about an image or a manifest.

        A Trivy image finding's component is the image; a Polaris manifest finding has no image at
        all and falls back to the Kubernetes resource name.
        """
        findings = self.by_uid("fairwinds_many_vuln.json")
        image_item = findings["5001"]
        self.assertEqual("registry.example.com/generic-api", image_item.component_name)
        self.assertEqual("1.4.0", image_item.component_version)

        manifest_item = findings["5002"]
        self.assertEqual("generic-worker", manifest_item.component_name)
        self.assertIsNone(manifest_item.component_version)

    def test_the_resource_line_joins_the_kubernetes_coordinates(self):
        finding = self.parse("fairwinds_one_vuln.json")[0]
        self.assertIn(
            "**Resource:** generic-app/Deployment/generic-api (container: api)",
            finding.description,
        )

    def test_the_container_qualifier_is_omitted_when_there_is_none(self):
        finding = self.by_uid("fairwinds_many_vuln.json")["5002"]
        self.assertIn("**Resource:** generic-app/Deployment/generic-worker", finding.description)
        self.assertNotIn("container:", finding.description)

    def test_a_missing_coordinate_segment_is_skipped(self):
        """The namespace is empty on this item, so the line is just kind/name."""
        finding = self.by_uid("fairwinds_many_vuln.json")["5003"]
        self.assertIn("**Resource:** Pod/debug-pod", finding.description)

    def test_an_item_with_no_coordinates_has_no_resource_line(self):
        finding = self.by_uid("fairwinds_many_vuln.json")["5004"]
        self.assertNotIn("**Resource:**", finding.description)

    def test_the_description_carries_the_image_event_type_and_notes(self):
        findings = self.by_uid("fairwinds_many_vuln.json")
        first = findings["5001"]
        self.assertIn("The image ships a vulnerable openssl.", first.description)
        self.assertIn("**Image:** registry.example.com/generic-api:1.4.0", first.description)
        self.assertIn("**Notes:** Raised by the platform team.", first.description)
        # Only the OPA item has an event type.
        self.assertNotIn("**Event type:**", first.description)
        self.assertIn("**Event type:** admission", findings["5003"].description)

    def test_html_in_the_description_is_flattened(self):
        finding = self.parse("fairwinds_one_vuln.json")[0]
        self.assertIn("The image ships a vulnerable openssl.", finding.description)
        self.assertNotIn("<p>", finding.description)

    def test_an_item_with_no_title_is_named_from_its_id(self):
        finding = self.by_uid("fairwinds_many_vuln.json")["5004"]
        self.assertEqual("Fairwinds action item 5004", finding.title)

    def test_tags_mirror_the_connector(self):
        finding = self.parse("fairwinds_one_vuln.json")[0]
        self.assertEqual(
            ["tool:trivy", "category:security", "cluster:generic-prod",
             "namespace:generic-app", "owner/platform"],
            finding.unsaved_tags,
        )

    def test_the_cluster_tag_is_added_even_when_empty(self):
        """
        The connector adds it unconditionally, so an item with no cluster gets a bare "cluster:" tag.

        Reproduced rather than tidied - tidying it here would be a difference between a file import
        and an API sync for the same item.
        """
        finding = self.by_uid("fairwinds_many_vuln.json")["5004"]
        self.assertEqual(["cluster:"], finding.unsaved_tags)

    def test_the_event_type_becomes_a_tag_too(self):
        finding = self.by_uid("fairwinds_many_vuln.json")["5003"]
        self.assertIn("event:admission", finding.unsaved_tags)

    def test_cves_are_extracted_from_the_title_and_description(self):
        """Fairwinds has no CVE field, so the connector scans the prose."""
        finding = self.parse("fairwinds_one_vuln.json")[0]
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        # And an item with no CVE anywhere has none.
        self.assertIsNone(
            self.by_uid("fairwinds_many_vuln.json")["5002"].unsaved_vulnerability_ids,
        )

    def test_no_mitigation_when_fairwinds_gives_no_remediation(self):
        finding = self.by_uid("fairwinds_many_vuln.json")["5003"]
        self.assertIsNone(finding.mitigation)

    def test_an_envelope_is_accepted(self):
        item = {"ID": 1, "Title": "An item", "Severity": 0.5, "Cluster": "c"}
        for payload in ({"ActionItems": [item]}, {"items": [item]}, {"data": [item]}):
            report = io.StringIO(json.dumps(payload))
            self.assertEqual(
                1, len(list(FairwindsParser().get_findings(report, Test()))), payload,
            )

    def test_a_repeated_item_id_collapses(self):
        item = {"ID": 1, "Title": "An item", "Severity": 0.5}
        report = io.StringIO(json.dumps([item, item]))
        self.assertEqual(1, len(list(FairwindsParser().get_findings(report, Test()))))

    def test_an_unexpected_shape_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(FairwindsParser().get_findings(io.StringIO('"nope"'), Test()))
        self.assertIn("ActionItems", str(raised.exception))
