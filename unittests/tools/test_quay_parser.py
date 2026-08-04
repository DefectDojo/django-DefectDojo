import io
import json

from dojo.models import Finding, Test
from dojo.tools.quay.parser import QuayParser, inert_text
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestQuayParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("quay") / filename
        with path.open(encoding="utf-8") as file:
            return list(QuayParser().get_findings(file, Test()))

    def by_uid(self, filename):
        return {f.unique_id_from_tool: f for f in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Quay connector's ScanType() verbatim.

        Any drift and a customer who uploads an export and also syncs the API gets two
        un-deduplicated copies of every finding.
        """
        parser = QuayParser()
        self.assertEqual(["Quay - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "Quay - Connectors Import",
            parser.get_label_for_scan_types("Quay - Connectors Import"),
        )

    def test_no_vuln(self):
        """A scanned image with features but no vulnerabilities on any of them."""
        self.assertEqual(0, len(self.parse("quay_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("quay_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's converter."""
        findings = self.parse("quay_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("CVE-2000-0001 - (openssl, 3.0.11-1)", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("openssl", finding.component_name)
        self.assertEqual("3.0.11-1", finding.component_version)
        self.assertEqual("CVE-2000-0001", finding.vuln_id_from_tool)
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual("3.0.13-1", finding.mitigation)
        self.assertEqual("https://example.com/advisories/cve-2000-0001", finding.references)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

    def test_the_clair_nesting_and_capitalised_keys_are_read(self):
        """
        Quay's scanner is Clair, so the report nests vulnerabilities under the features they affect
        and capitalises the JSON keys - "Layer", "Features", "Name", "Severity".

        Reading lower-case keys, or expecting a flat vulnerability list, would import nothing at all
        without erroring.
        """
        raw = json.loads((get_unit_tests_scans_path("quay")
                          / "quay_one_vuln.json").read_text(encoding="utf-8"))
        self.assertIn("Layer", raw["data"])
        self.assertIn("Features", raw["data"]["Layer"])
        feature = raw["data"]["Layer"]["Features"][0]
        self.assertIn("Name", feature)
        self.assertNotIn("name", feature)
        self.assertIn("Vulnerabilities", feature)

        self.assertEqual(1, len(self.parse("quay_one_vuln.json")))

    def test_one_finding_per_feature_and_vulnerability_pair(self):
        """
        A feature can carry several vulnerabilities, and each is its own finding.

        A feature with an empty vulnerability list contributes nothing.
        """
        findings = self.parse("quay_many_vuln.json")
        self.assertEqual(4, len(findings))
        self.assertEqual(
            {"openssl", "curl", "zlib"}, {f.component_name for f in findings},
        )
        # openssl carries two.
        self.assertEqual(2, sum(1 for f in findings if f.component_name == "openssl"))
        # busybox has no vulnerabilities and so no findings.
        self.assertNotIn("busybox", {f.component_name for f in findings})

    def test_clairs_defcon1_severity_is_critical(self):
        """
        Clair grades "Defcon1" above Critical, and DefectDojo has nothing higher.

        Not mapping it would drop the most severe grade Clair can report to Info.
        """
        finding = self.by_uid("quay_many_vuln.json")["CVE-2000-0002openssl"]
        self.assertEqual("Critical", finding.severity)

    def test_the_severity_mapping_directly(self):
        parser = QuayParser()
        for value, expected in [
            ("Critical", "Critical"), ("Defcon1", "Critical"), ("defcon1", "Critical"),
            ("High", "High"), ("Medium", "Medium"), ("Low", "Low"),
            ("Negligible", "Info"), ("", "Info"),
        ]:
            finding = parser.build_finding({"Name": "p"}, {"Name": "V", "Severity": value}, "", Test())
            self.assertEqual(expected, finding.severity, value)

    def test_the_unique_id_concatenates_with_no_separator(self):
        """
        The connector builds this as advisory id + feature name, with nothing between them.

        Reproduced exactly: inserting a separator would give every finding a different tool id from
        the connector's and break the merge this parser exists for.
        """
        uids = set(self.by_uid("quay_many_vuln.json"))
        self.assertIn("CVE-2000-0001openssl", uids)
        self.assertIn("CVE-2000-0003curl", uids)

    def test_every_finding_says_no_impact_provided(self):
        """Clair supplies no impact assessment, and the connector states that rather than blanking it."""
        for finding in self.parse("quay_many_vuln.json"):
            self.assertEqual("No impact provided", finding.impact)

    def test_the_description_block_is_the_connectors(self):
        finding = self.parse("quay_one_vuln.json")[0]
        self.assertIn("A flaw in certificate verification", finding.description)
        self.assertIn("**Vulnerable feature:** openssl", finding.description)
        self.assertIn("**Vulnerable version:** 3.0.11-1", finding.description)
        self.assertIn("**Fixed by:** 3.0.13-1", finding.description)
        self.assertIn("**Namespace:** debian:12", finding.description)
        self.assertIn("**CVE:** CVE-2000-0001", finding.description)
        self.assertIn("**Image tag:** 1.4.0", finding.description)

    def test_the_fix_namespace_and_cve_lines_appear_even_when_empty(self):
        """
        The connector writes these unconditionally.

        Omitting the empty ones would make a file import read differently from an API sync for the
        same finding, which is the whole thing this parser is trying to avoid.
        """
        finding = self.by_uid("quay_many_vuln.json")["CVE-2000-0004zlib"]
        self.assertIn("**Fixed by:** \n", finding.description + "\n")
        self.assertIn("**Namespace:** \n", finding.description + "\n")
        self.assertIn("**CVE:** CVE-2000-0004", finding.description)

    def test_advisory_html_is_flattened_not_rendered(self):
        """
        Clair advisory text comes from upstream distro trackers.

        It is flattened and escaped, so nothing from an upstream tracker can be injected into a
        rendered finding.
        """
        finding = self.by_uid("quay_many_vuln.json")["CVE-2000-0003curl"]
        self.assertIn("A flaw in URL parsing.", finding.description)
        self.assertNotIn("alert(", finding.description)
        self.assertNotIn("<script", finding.description)
        # And the paragraph markup on the one_vuln advisory does not survive either.
        first = self.parse("quay_one_vuln.json")[0]
        self.assertNotIn("<p>", first.description)

    def test_the_inert_text_helper_matches_gos_entities(self):
        self.assertEqual("plain", inert_text("plain"))
        self.assertEqual("kept", inert_text("<script>dropped()</script>kept"))
        self.assertEqual("a\n\nb", inert_text("<p>a</p><p>b</p>"))
        self.assertEqual("&#39;q&#39;", inert_text("'q'"))
        self.assertEqual("", inert_text(""))

    def test_no_mitigation_or_references_when_clair_has_none(self):
        finding = self.by_uid("quay_many_vuln.json")["CVE-2000-0004zlib"]
        self.assertIsNone(finding.mitigation)
        self.assertIsNone(finding.references)

    def test_the_image_tag_is_omitted_when_the_export_does_not_carry_it(self):
        """
        The tag is not in Clair's output - the connector supplies it from the tag it scanned.

        An export without one still imports; the tag line is simply absent.
        """
        report = io.StringIO(json.dumps({"data": {"Layer": {"Features": [
            {"Name": "openssl", "Version": "3.0.11-1", "Vulnerabilities": [
                {"Name": "CVE-2000-0001", "Severity": "High"},
            ]},
        ]}}}))
        finding = list(QuayParser().get_findings(report, Test()))[0]
        self.assertNotIn("**Image tag:**", finding.description)

    def test_a_bare_layer_or_features_list_is_accepted(self):
        features = [{"Name": "p", "Version": "1", "Vulnerabilities": [
            {"Name": "CVE-2000-0001", "Severity": "Low"},
        ]}]
        for payload in ({"Layer": {"Features": features}}, {"Features": features}, features):
            report = io.StringIO(json.dumps(payload))
            self.assertEqual(
                1, len(list(QuayParser().get_findings(report, Test()))), payload,
            )

    def test_a_repeated_pair_collapses(self):
        vuln = {"Name": "CVE-2000-0001", "Severity": "Low"}
        report = io.StringIO(json.dumps({"data": {"Layer": {"Features": [
            {"Name": "p", "Version": "1", "Vulnerabilities": [vuln, vuln]},
        ]}}}))
        self.assertEqual(1, len(list(QuayParser().get_findings(report, Test()))))

    def test_an_unexpected_shape_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(QuayParser().get_findings(io.StringIO('"nope"'), Test()))
        self.assertIn("Layer", str(raised.exception))
