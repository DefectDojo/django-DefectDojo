import io
import json

from dojo.models import Finding, Test
from dojo.tools.endorlabs.parser import EndorLabsParser, inert_text
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestEndorLabsParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("endorlabs") / filename).open(encoding="utf-8") as file:
            return list(EndorLabsParser().get_findings(file, Test()))

    def by_uid(self, filename):
        return {f.unique_id_from_tool: f for f in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Endor Labs connector's ScanType() verbatim.

        Any drift and a customer who uploads an export and also syncs the API gets two
        un-deduplicated copies of every finding.
        """
        parser = EndorLabsParser()
        self.assertEqual(["Endor Labs - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "Endor Labs - Connectors Import",
            parser.get_label_for_scan_types("Endor Labs - Connectors Import"),
        )

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("endorlabs_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("endorlabs_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring FindingConverter.Convert in the connector."""
        findings = self.parse("endorlabs_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("CVE-2000-0001 in generic-lib", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("generic-lib", finding.component_name)
        self.assertEqual("1.2.3", finding.component_version)
        self.assertEqual("00000000-0000-4000-8000-000000000001", finding.unique_id_from_tool)
        self.assertEqual("CVE-2000-0001", finding.vuln_id_from_tool)
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", finding.cvssv3)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

    def test_reachability_is_the_finding_impact(self):
        """
        Reachability is Endor's distinguishing signal, so the connector promotes it to impact.

        Leaving it only in tags would hide the one thing that separates Endor from any other SCA
        tool: whether the vulnerable code is actually called.
        """
        finding = self.parse("endorlabs_one_vuln.json")[0]
        self.assertEqual("Reachable (vulnerable function is called)", finding.impact)
        self.assertIn("**Reachability**: Reachable (vulnerable function is called)",
                      finding.description)

    def test_the_reachability_precedence_is_the_connectors(self):
        """
        A function verdict outranks a dependency verdict, and a definite verdict outranks a maybe.

        Getting the order wrong would report "potentially reachable" for a finding Endor confirmed
        reachable.
        """
        parser = EndorLabsParser()
        self.assertEqual(
            "Reachable (vulnerable function is called)",
            parser.reachability_summary([
                "FINDING_TAGS_POTENTIALLY_REACHABLE_FUNCTION",
                "FINDING_TAGS_REACHABLE_DEPENDENCY",
                "FINDING_TAGS_REACHABLE_FUNCTION",
            ]),
        )
        self.assertEqual(
            "Unreachable (vulnerable function is not called)",
            parser.reachability_summary([
                "FINDING_TAGS_UNREACHABLE_FUNCTION", "FINDING_TAGS_REACHABLE_DEPENDENCY",
            ]),
        )
        self.assertEqual(
            "Reachable (dependency is used)",
            parser.reachability_summary(["FINDING_TAGS_REACHABLE_DEPENDENCY"]),
        )
        self.assertEqual("", parser.reachability_summary(["FINDING_TAGS_DIRECT"]))

    def test_all_vulnerability_ids_are_imported_with_the_primary_first(self):
        """The primary identifier then Endor's aliases, deduplicated - the alias repeats the CVE."""
        finding = self.parse("endorlabs_one_vuln.json")[0]
        self.assertEqual(
            ["CVE-2000-0001", "GHSA-0000-0000-0001"], finding.unsaved_vulnerability_ids,
        )

    def test_the_description_is_assembled_in_the_converters_order(self):
        finding = self.parse("endorlabs_one_vuln.json")[0]
        self.assertIn("generic-lib is vulnerable to remote code execution.", finding.description)
        self.assertIn("**Explanation**:", finding.description)
        self.assertIn("**Vulnerability**: Remote code execution in generic-lib.",
                      finding.description)
        self.assertIn("**EPSS probability**: 0.0423", finding.description)
        self.assertIn("**References**:\n- https://example.com/advisories/cve-2000-0001",
                      finding.description)
        self.assertLess(
            finding.description.index("**Explanation**:"),
            finding.description.index("**Reachability**:"),
        )
        self.assertLess(
            finding.description.index("**EPSS probability**:"),
            finding.description.index("**References**:"),
        )

    def test_html_in_advisory_text_is_flattened_not_rendered(self):
        """
        Endor advisory text arrives as HTML, sourced from upstream advisories.

        The connector's InertText drops script and style content, turns block tags into newlines and
        escapes the result, so nothing can be injected into a rendered finding.
        """
        finding = self.parse("endorlabs_one_vuln.json")[0]
        self.assertIn("The parse() helper evaluates untrusted input.", finding.description)
        # The script content is dropped entirely, and no raw markup survives.
        self.assertNotIn("alert(", finding.description)
        self.assertNotIn("<script", finding.description)
        self.assertNotIn("<b>", finding.description)
        self.assertNotIn("<p>", finding.description)

    def test_the_inert_text_helper_directly(self):
        """Mirrors the connector's InertText, including Go's apostrophe entity."""
        self.assertEqual("plain", inert_text("plain"))
        # Both the open and close tag emit a newline, so a paragraph break survives as a blank line.
        self.assertEqual("a\n\nb", inert_text("<p>a</p><p>b</p>"))
        # A single block boundary leaves one newline.
        self.assertEqual("a\nb", inert_text("a<br>b"))
        self.assertEqual("kept", inert_text("<script>dropped()</script>kept"))
        self.assertEqual("kept", inert_text("<style>.x{}</style>kept"))
        # Go's html.EscapeString spells these entities this way.
        self.assertEqual("&lt;b&gt;", inert_text("&lt;b&gt;"))
        self.assertEqual("a &amp; b", inert_text("a &amp; b"))
        self.assertEqual("&#39;quoted&#39;", inert_text("'quoted'"))
        self.assertEqual("&#34;quoted&#34;", inert_text('"quoted"'))
        # Runs of blank lines collapse, and trailing blanks are dropped.
        self.assertEqual("a\n\nb", inert_text("a<p></p><p></p>b<br><br>"))
        self.assertEqual("", inert_text(""))

    def test_the_cvss_score_falls_back_to_the_v4_base_score(self):
        """
        Endor publishes both v3 and v4, and the connector prefers v3.

        A v4-only advisory would otherwise import with no score at all.
        """
        finding = self.by_uid("endorlabs_many_vuln.json")["00000000-0000-4000-8000-000000000002"]
        self.assertEqual(7.7, finding.cvssv3_score)
        # No v3 block, so no vector.
        self.assertIsNone(finding.cvssv3)

    def test_the_component_falls_back_to_the_package_name(self):
        finding = self.by_uid("endorlabs_many_vuln.json")["00000000-0000-4000-8000-000000000002"]
        self.assertEqual("pypi://generic-parser", finding.component_name)
        self.assertEqual("3.1.0", finding.component_version)

    def test_a_finding_with_no_name_is_titled_from_the_vulnerability_and_component(self):
        finding = self.by_uid("endorlabs_many_vuln.json")["00000000-0000-4000-8000-000000000002"]
        self.assertEqual("GHSA-0000-0000-0002 in pypi://generic-parser:3.1.0", finding.title)

    def test_a_finding_with_no_uuid_falls_back_to_a_composite_id(self):
        """The converter's uniqueID(): "<vuln id>|<component>:<version>" when Endor sends no UUID."""
        uids = set(self.by_uid("endorlabs_many_vuln.json"))
        self.assertIn("CVE-2000-0003|generic-widget:4.0.0", uids)

    def test_an_unrecognised_level_is_clamped_to_info(self):
        finding = self.by_uid("endorlabs_many_vuln.json")["00000000-0000-4000-8000-000000000004"]
        self.assertEqual("Info", finding.severity)

    def test_tags_are_humanised_and_the_unspecified_placeholders_dropped(self):
        """
        The enum prefix is stripped, the rest lower-cased and hyphenated.

        A tag ending _UNSPECIFIED only says Endor did not determine it, so it carries no information
        and is dropped rather than imported as a meaningless label.
        """
        finding = self.parse("endorlabs_one_vuln.json")[0]
        self.assertEqual(
            ["reachable-function", "direct", "fix-available", "vulnerability", "sca"],
            finding.unsaved_tags,
        )
        self.assertNotIn("unspecified", finding.unsaved_tags)

        other = self.by_uid("endorlabs_many_vuln.json")["00000000-0000-4000-8000-000000000004"]
        self.assertEqual(["secrets"], other.unsaved_tags)

    def test_a_finding_with_no_vulnerability_still_imports(self):
        """Endor reports secrets and other non-CVE findings with no vulnerability block at all."""
        finding = self.by_uid("endorlabs_many_vuln.json")["00000000-0000-4000-8000-000000000004"]
        self.assertEqual("Secret committed in generic-app", finding.title)
        self.assertIsNone(finding.vuln_id_from_tool)
        self.assertIsNone(finding.unsaved_vulnerability_ids)
        self.assertIsNone(finding.cvssv3_score)
        self.assertIsNone(finding.impact)

    def test_remediation_becomes_the_mitigation(self):
        finding = self.parse("endorlabs_one_vuln.json")[0]
        self.assertEqual("Upgrade generic-lib to 1.2.4 or later.", finding.mitigation)

    def test_a_bare_objects_envelope_and_a_bare_array_are_accepted(self):
        row = {"uuid": "u1", "meta": {"name": "A finding"},
               "spec": {"level": "FINDING_LEVEL_LOW"}}
        for payload in ({"objects": [row]}, [row]):
            report = io.StringIO(json.dumps(payload))
            findings = list(EndorLabsParser().get_findings(report, Test()))
            self.assertEqual(1, len(findings), payload)
            self.assertEqual("Low", findings[0].severity)

    def test_a_repeated_uuid_collapses(self):
        row = {"uuid": "same", "meta": {"name": "A finding"},
               "spec": {"level": "FINDING_LEVEL_LOW"}}
        report = io.StringIO(json.dumps({"list": {"objects": [row, row]}}))
        self.assertEqual(1, len(list(EndorLabsParser().get_findings(report, Test()))))

    def test_an_unexpected_shape_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(EndorLabsParser().get_findings(io.StringIO('"nope"'), Test()))
        self.assertIn("objects", str(raised.exception))
