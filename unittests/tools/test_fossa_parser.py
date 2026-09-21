import io
import json
from datetime import date

from dojo.models import Finding, Test
from dojo.tools.fossa.parser import FossaParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestFossaParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("fossa") / filename).open(encoding="utf-8") as file:
            return list(FossaParser().get_findings(file, Test()))

    def by_uid(self, filename):
        return {f.unique_id_from_tool: f for f in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the FOSSA connector's ScanType() verbatim.

        Any drift and a customer who uploads an export and also syncs the API gets two
        un-deduplicated copies of every finding.
        """
        parser = FossaParser()
        self.assertEqual(["FOSSA - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "FOSSA - Connectors Import",
            parser.get_label_for_scan_types("FOSSA - Connectors Import"),
        )

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("fossa_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("fossa_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring IssueToFinding in the connector's converter."""
        findings = self.parse("fossa_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        # converter vulnerabilityTitle(): "<CVE> - <package> (<version>)"
        self.assertEqual("CVE-2000-0001 - generic-lib (1.2.3)", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("generic-lib", finding.component_name)
        self.assertEqual("1.2.3", finding.component_version)
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", finding.cvssv3)
        # converter cweNumber(): first parseable, "CWE-1321" -> 1321.
        self.assertEqual(1321, finding.cwe)
        self.assertEqual(date(2026, 5, 11), finding.date)
        self.assertTrue(finding.active)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        # converter: "<issue id>:<project locator>"
        self.assertEqual("1001:custom+1/generic-app", finding.unique_id_from_tool)

    def test_the_unique_id_is_suffixed_with_the_project_locator(self):
        """
        One FOSSA issue can affect several projects, and the connector emits one finding per project.

        Without the locator suffix those findings would share a tool id, and DefectDojo would treat
        the same dependency issue in two products as one finding.
        """
        findings = self.parse("fossa_many_vuln.json")
        shared = [f for f in findings if f.unique_id_from_tool.startswith("1001:")]
        self.assertEqual(2, len(shared))
        self.assertEqual(
            {"1001:custom+1/generic-app", "1001:custom+1/generic-service"},
            {f.unique_id_from_tool for f in shared},
        )
        # Same issue, so the same title and severity - only the tool id differs.
        self.assertEqual({"CVE-2000-0001 - generic-lib (1.2.3)"}, {f.title for f in shared})

    def test_an_export_with_no_project_context_uses_the_issue_id_alone(self):
        """An export carrying no projects cannot reproduce the connector's suffix."""
        report = io.StringIO(json.dumps({"issues": [
            {"id": 42, "type": "vulnerability", "cve": "CVE-2000-0001", "severity": "high",
             "source": {"name": "generic-lib", "version": "1.0.0"}},
        ]}))
        finding = list(FossaParser().get_findings(report, Test()))[0]
        self.assertEqual("42", finding.unique_id_from_tool)

    def test_the_description_mirrors_the_converters_order(self):
        finding = self.parse("fossa_one_vuln.json")[0]
        self.assertIn("A crafted payload can pollute", finding.description)
        self.assertIn("**Package:** npm+generic-lib$1.2.3", finding.description)
        self.assertIn("**Dependency:** generic-lib@1.2.3", finding.description)
        self.assertIn("**Package manager:** npm", finding.description)
        self.assertIn("**Dependency depths:** direct 1, transitive 3", finding.description)
        self.assertIn("**FOSSA issue ID:** 1001", finding.description)
        self.assertIn("**Affected versions:** <1.2.4", finding.description)
        self.assertIn("**Patched versions:** >=1.2.4", finding.description)
        self.assertIn("**CWEs:** CWE-1321, CWE-20", finding.description)
        self.assertIn("**Published:** 2026-05-01", finding.description)
        self.assertIn("**CVE status:** PUBLISHED", finding.description)
        # The converter writes the package block before the version-range lines.
        self.assertLess(
            finding.description.index("**FOSSA issue ID:**"),
            finding.description.index("**Affected versions:**"),
        )

    def test_mitigation_puts_the_complete_fix_first(self):
        """The converter's mitigation(): the fix that resolves the issue leads, each with its semver distance."""
        finding = self.parse("fossa_one_vuln.json")[0]
        self.assertEqual(
            "**Complete fix:** upgrade to 2.0.0 (MAJOR version bump)\n"
            "**Partial fix:** upgrade to 1.2.4 (PATCH version bump)",
            finding.mitigation,
        )

    def test_a_partial_fix_with_no_distance_omits_the_parenthetical(self):
        finding = self.by_uid("fossa_many_vuln.json")["1002:custom+1/generic-app"]
        self.assertEqual("**Partial fix:** upgrade to 3.1.1", finding.mitigation)

    def test_references_accept_both_a_link_object_and_a_bare_string(self):
        """
        FOSSA sends a reference either way, and the connector's Reference.Link() handles both.

        Rejecting the bare-string form would silently drop references.
        """
        finding = self.parse("fossa_one_vuln.json")[0]
        self.assertEqual(
            "https://example.com/advisories/cve-2000-0001\nhttps://example.com/commit/abcdef1",
            finding.references,
        )

    def test_a_reference_object_with_only_a_title_falls_back_to_it(self):
        report = io.StringIO(json.dumps({"issues": [
            {"id": 7, "cve": "CVE-2000-0001", "severity": "low",
             "references": [{"url": "", "title": "Vendor bulletin 7"}]},
        ]}))
        finding = list(FossaParser().get_findings(report, Test()))[0]
        self.assertEqual("Vendor bulletin 7", finding.references)

    def test_severity_falls_back_to_the_cvss_bands_when_fossa_says_unknown(self):
        """
        The converter's vulnerabilitySeverity(): FOSSA reports "unknown" often enough for this to matter.

        A 7.5 with severity "unknown" must become High, not Info.
        """
        finding = self.by_uid("fossa_many_vuln.json")["1002:custom+1/generic-app"]
        self.assertEqual("High", finding.severity)

    def test_the_cvss_bands_directly(self):
        parser = FossaParser()
        for score, expected in [
            (10.0, "Critical"), (9.0, "Critical"), (8.9, "High"), (7.0, "High"),
            (6.9, "Medium"), (4.0, "Medium"), (3.9, "Low"), (0.1, "Low"), (0, "Info"),
        ]:
            self.assertEqual(expected, parser.severity_from_cvss(score), score)

    def test_an_issue_is_treated_as_a_vulnerability_when_it_carries_cve_fields(self):
        """
        The converter's isVulnerability(): the type check is backed up by the vulnerability-only fields.

        A missing or renamed type value must not silently downgrade a CVE to a licensing finding,
        which would also change how it is severity-graded.
        """
        finding = self.by_uid("fossa_many_vuln.json")["1006:custom+1/generic-app"]
        self.assertEqual("CVE-2000-0006", finding.title)
        self.assertEqual(["CVE-2000-0006"], finding.unsaved_vulnerability_ids)
        self.assertIn("category:vulnerability", finding.unsaved_tags)
        # cvss 0 and no severity, so the bands give Info rather than a licensing grade.
        self.assertEqual("Info", finding.severity)

    def test_a_licensing_issue_is_titled_and_graded_from_the_type_table(self):
        finding = self.by_uid("fossa_many_vuln.json")["1003:custom+1/generic-app"]
        self.assertEqual(
            "policy_conflict - GPL-3.0-only in com.example:generic-widget", finding.title,
        )
        self.assertEqual("High", finding.severity)
        self.assertIn("**Issue type:** policy_conflict", finding.description)
        self.assertIn("**License:** GPL-3.0-only", finding.description)
        # Licensing issues carry none of the vulnerability-only fields.
        self.assertIsNone(finding.mitigation)
        self.assertIsNone(finding.references)
        self.assertIsNone(finding.cvssv3_score)
        self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_both_spellings_of_the_risk_types_are_graded(self):
        """
        FOSSA's docs table hyphenates (risk_empty-package); fossa-cli's wire format uses underscores.

        Mapping only one spelling would drop the other to Info.
        """
        parser = FossaParser()
        for issue_type in ("risk_empty-package", "risk_empty_package",
                           "risk_native-code", "risk_native_code"):
            self.assertEqual("Low", parser.severity({"type": issue_type}), issue_type)
        # Confirmed against the fixture too, not just the table.
        finding = self.by_uid("fossa_many_vuln.json")["1004:custom+1/generic-app"]
        self.assertEqual("Low", finding.severity)

    def test_an_unrecognised_risk_type_is_still_low_and_anything_else_is_info(self):
        """The converter's severity(): an unknown risk_* signal is quality noise; other types are unknown."""
        parser = FossaParser()
        self.assertEqual("Low", parser.severity({"type": "risk_something_new"}))
        self.assertEqual("Info", parser.severity({"type": "some_new_type_fossa_added"}))
        finding = self.by_uid("fossa_many_vuln.json")["1005:custom+1/generic-app"]
        self.assertEqual("Info", finding.severity)

    def test_an_unparseable_cwe_list_leaves_the_cwe_at_zero(self):
        """
        The converter's cweNumber() returns ok=false, so the converter never assigns Cwe.

        Finding.cwe is an IntegerField with default 0, so this reads as 0 rather than None.
        """
        finding = self.by_uid("fossa_many_vuln.json")["1002:custom+1/generic-app"]
        self.assertEqual(0, finding.cwe)

    def test_a_date_only_timestamp_is_accepted(self):
        """The converter's findingDate() falls back to the leading date portion."""
        finding = self.by_uid("fossa_many_vuln.json")["1004:custom+1/generic-app"]
        self.assertEqual(date(2026, 5, 14), finding.date)

    def test_an_unparseable_timestamp_leaves_the_date_unset(self):
        finding = self.by_uid("fossa_many_vuln.json")["1005:custom+1/generic-app"]
        self.assertIsNone(finding.date)

    def test_a_vulnerability_with_no_identifier_falls_back_to_the_issue_title(self):
        report = io.StringIO(json.dumps({"issues": [
            {"id": 9, "type": "vulnerability", "title": "Unnamed advisory", "severity": "medium"},
        ]}))
        self.assertEqual(
            "Unnamed advisory", list(FossaParser().get_findings(report, Test()))[0].title,
        )

    def test_a_vulnerability_with_neither_identifier_nor_title_names_the_issue_id(self):
        report = io.StringIO(json.dumps({"issues": [
            {"id": 9, "type": "vulnerability", "severity": "medium"},
        ]}))
        self.assertEqual(
            "FOSSA vulnerability 9", list(FossaParser().get_findings(report, Test()))[0].title,
        )

    def test_tags_mirror_the_converter(self):
        finding = self.parse("fossa_one_vuln.json")[0]
        self.assertEqual(
            ["fossa:vulnerability", "category:vulnerability", "package-manager:npm",
             "npm+generic-lib$1.2.3"],
            finding.unsaved_tags,
        )

    def test_a_bare_issues_array_is_accepted(self):
        report = io.StringIO(json.dumps([
            {"id": 1, "type": "vulnerability", "cve": "CVE-2000-0001", "severity": "low"},
        ]))
        self.assertEqual(1, len(list(FossaParser().get_findings(report, Test()))))

    def test_an_unexpected_shape_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(FossaParser().get_findings(io.StringIO('"nope"'), Test()))
        self.assertIn("issues", str(raised.exception))
