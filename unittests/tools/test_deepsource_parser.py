import io
import json
from datetime import UTC, date, datetime

from dojo.models import Finding, Test
from dojo.tools.deepsource.parser import DeepSourceParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDeepSourceParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("deepsource") / filename).open(encoding="utf-8") as file:
            return list(DeepSourceParser().get_findings(file, Test()))

    def by_uid(self, filename):
        return {f.unique_id_from_tool: f for f in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the DeepSource connector's ScanType() verbatim.

        Any drift and a customer who uploads an export and also syncs the API gets two
        un-deduplicated copies of every finding.
        """
        parser = DeepSourceParser()
        self.assertEqual(["DeepSource - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "DeepSource - Connectors Import",
            parser.get_label_for_scan_types("DeepSource - Connectors Import"),
        )

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("deepsource_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("deepsource_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring OccurrenceToFinding in the connector's converter."""
        findings = self.parse("deepsource_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Possible SQL injection through string formatting", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("src/generic_app/views.py", finding.file_path)
        self.assertEqual(42, finding.line)
        self.assertEqual("occ-0001", finding.unique_id_from_tool)
        self.assertEqual("PY-A6006", finding.vuln_id_from_tool)
        self.assertTrue(finding.active)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        # The run's finish time dates the finding, not its creation time.
        self.assertEqual(date(2026, 6, 20), finding.date)

        self.assertIn("Query is built with string formatting", finding.description)
        self.assertIn("**Issue:** PY-A6006", finding.description)
        self.assertIn("**Analyzer:** Python (python)", finding.description)
        self.assertIn("**Category:** SECURITY", finding.description)
        self.assertIn("**DeepSource severity:** CRITICAL", finding.description)
        # A genuine multi-line span is rendered as a range.
        self.assertIn("**Location:** src/generic_app/views.py:42-47", finding.description)
        self.assertEqual(["python", "SECURITY", "CRITICAL"], finding.unsaved_tags)

    def test_a_security_issue_keeps_its_grade_but_a_bug_risk_issue_drops_a_step(self):
        """
        DeepSource grades everything CRITICAL / MAJOR / MINOR whatever the issue actually is.

        So the category has to decide which ladder applies. A CRITICAL security issue is Critical; a
        CRITICAL bug-risk issue is High, because it describes a defect rather than a weakness.
        Applying one ladder to both would either inflate every lint finding or bury real ones.
        """
        findings = self.by_uid("deepsource_many_vuln.json")
        self.assertEqual("Critical", findings["occ-0001"].severity)   # SECURITY + CRITICAL
        self.assertEqual("High", findings["occ-0002"].severity)       # BUG_RISK + CRITICAL

    def test_both_severity_ladders_directly(self):
        parser = DeepSourceParser()
        for category, pairs in (
            ("SECURITY", [("CRITICAL", "Critical"), ("MAJOR", "High"), ("MINOR", "Medium")]),
            ("BUG_RISK", [("CRITICAL", "High"), ("MAJOR", "Medium"), ("MINOR", "Low")]),
            ("PERFORMANCE", [("CRITICAL", "High"), ("MINOR", "Low")]),
            ("TYPECHECK", [("MAJOR", "Medium")]),
            ("ANTI_PATTERN", [("MAJOR", "Medium")]),
        ):
            for severity, expected in pairs:
                self.assertEqual(
                    expected,
                    parser.severity_for_issue({"category": category, "severity": severity}),
                    f"{category}/{severity}",
                )

    def test_style_documentation_and_coverage_are_info(self):
        """
        These categories are not weaknesses, and the connector grades them Info.

        Mirrored rather than corrected, since parity with the connector is what stops findings
        duplicating. Raised in the PR as a follow-up worth discussing against the connector.
        """
        parser = DeepSourceParser()
        for category in ("STYLE", "DOCUMENTATION", "COVERAGE"):
            self.assertEqual(
                "Info", parser.severity_for_issue({"category": category, "severity": "CRITICAL"}),
                category,
            )
        finding = self.by_uid("deepsource_many_vuln.json")["occ-0003"]
        self.assertEqual("Info", finding.severity)

    def test_a_secrets_analyzer_hit_is_critical_whatever_deepsource_graded_it(self):
        """
        A committed credential is a committed credential.

        The fixture grades it MINOR, which on the security ladder would be Medium; the analyzer
        override is what makes it Critical.
        """
        finding = self.by_uid("deepsource_many_vuln.json")["occ-0004"]
        self.assertEqual("Critical", finding.severity)
        self.assertIn("secrets", finding.unsaved_tags)
        self.assertIn("MINOR", finding.unsaved_tags)

    def test_an_unrecognised_category_is_info(self):
        finding = self.by_uid("deepsource_many_vuln.json")["occ-0005"]
        self.assertEqual("Info", finding.severity)

    def test_an_occurrence_with_no_title_falls_back_through_the_issue(self):
        findings = self.by_uid("deepsource_many_vuln.json")
        # No occurrence title, so the issue title is used.
        self.assertEqual("Mutable default argument", findings["occ-0002"].title)
        # No occurrence or issue title, and no shortcode either.
        self.assertEqual("DeepSource issue occ-0005", findings["occ-0005"].title)

    def test_a_single_line_occurrence_is_not_rendered_as_a_range(self):
        """An endLine equal to beginLine is one line, not a range."""
        finding = self.by_uid("deepsource_many_vuln.json")["occ-0002"]
        self.assertIn("**Location:** src/generic_app/utils.py:10", finding.description)
        self.assertNotIn(":10-10", finding.description)

    def test_an_occurrence_with_no_line_has_no_location(self):
        finding = self.by_uid("deepsource_many_vuln.json")["occ-0005"]
        self.assertIsNone(finding.line)
        self.assertIsNone(finding.file_path)
        self.assertNotIn("**Location:**", finding.description)

    def test_a_dependency_vulnerability_is_mapped_separately(self):
        """
        DeepSource reports analysis issues and dependency advisories, converted differently.

        Treating one shape as the other would lose the CVE, component and CVSS score entirely.
        """
        finding = self.by_uid("deepsource_many_vuln.json")["dep-0001"]
        self.assertEqual("CVE-2000-0001 - generic-lib (1.2.3)", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertEqual("generic-lib", finding.component_name)
        self.assertEqual("1.2.3", finding.component_version)
        self.assertEqual("CVE-2000-0001", finding.vuln_id_from_tool)
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertEqual(0.0431, finding.epss_score)
        self.assertEqual(date(2026, 5, 1), finding.date)
        self.assertEqual(
            "https://example.com/advisories/cve-2000-0001\nhttps://example.com/commit/abcdef1",
            finding.references,
        )
        self.assertEqual(["sca", "PYPI", "REACHABLE"], finding.unsaved_tags)

        self.assertIn("**Package:** generic-lib 1.2.3", finding.description)
        self.assertIn("**Ecosystem:** PYPI", finding.description)
        self.assertIn("**Reachability:** REACHABLE", finding.description)
        self.assertIn("**Fixability:** FIXABLE", finding.description)
        self.assertIn("**Aliases:** GHSA-0000-0000-0001, cve-2000-0001", finding.description)

    def test_advisory_identifiers_are_upper_cased_and_deduplicated(self):
        """The fixture repeats the identifier in lower case as an alias, to prove both."""
        finding = self.by_uid("deepsource_many_vuln.json")["dep-0001"]
        self.assertEqual(
            ["CVE-2000-0001", "GHSA-0000-0000-0001"], finding.unsaved_vulnerability_ids,
        )

    def test_an_unscored_advisory_is_graded_by_its_severity_word(self):
        """GitHub spells medium "MODERATE", so both have to map."""
        finding = self.by_uid("deepsource_many_vuln.json")["dep-0002"]
        self.assertEqual("Medium", finding.severity)
        self.assertIsNone(finding.cvssv3_score)

    def test_the_advisory_severity_resolution_directly(self):
        parser = DeepSourceParser()
        # A score always wins over the words.
        self.assertEqual("Critical", parser.severity_for_vulnerability(
            {"cvssV3BaseScore": 9.1, "severity": "LOW"}))
        # cvssV3Severity is consulted before the plain severity.
        self.assertEqual("High", parser.severity_for_vulnerability(
            {"cvssV3Severity": "HIGH", "severity": "LOW"}))
        self.assertEqual("Medium", parser.severity_for_vulnerability({"severity": "MODERATE"}))
        self.assertEqual("Info", parser.severity_for_vulnerability({"severity": "nonsense"}))

    def test_the_cvss_bands_bottom_out_at_low_not_info(self):
        """A scored advisory is never Info; the converter's lowest band is Low."""
        parser = DeepSourceParser()
        for score, expected in [(10.0, "Critical"), (9.0, "Critical"), (7.0, "High"),
                                (4.0, "Medium"), (0.1, "Low"), (2.1, "Low")]:
            self.assertEqual(expected, parser.cvss_band(score), score)
        finding = self.by_uid("deepsource_many_vuln.json")["dep-0004"]
        self.assertEqual("Low", finding.severity)

    def test_an_advisory_with_no_fix_says_so_explicitly(self):
        """
        "No fix published" is itself useful triage information.

        Leaving the mitigation empty would read as "nobody filled this in".
        """
        finding = self.by_uid("deepsource_many_vuln.json")["dep-0002"]
        self.assertEqual(
            "No fixed version has been published for this advisory.", finding.mitigation,
        )

    def test_several_fixed_versions_are_offered_as_alternatives(self):
        finding = self.by_uid("deepsource_many_vuln.json")["dep-0001"]
        self.assertEqual("Upgrade generic-lib to 1.2.4 or 2.0.0.", finding.mitigation)

    def test_an_advisory_with_no_package_name_still_gets_a_mitigation(self):
        parser = DeepSourceParser()
        self.assertEqual(
            "Upgrade the affected package to 1.0.1.",
            parser.vulnerability_mitigation({"fixedVersions": ["1.0.1"]}, {}),
        )

    def test_an_advisory_with_no_identifier_falls_back_to_its_summary(self):
        finding = self.by_uid("deepsource_many_vuln.json")["dep-0003"]
        self.assertEqual("An advisory with no identifier at all.", finding.title)
        self.assertIsNone(finding.vuln_id_from_tool)
        self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_an_unparseable_published_date_falls_back_to_today(self):
        """The converter always dates a finding; asserted as a range so it cannot flake."""
        finding = self.by_uid("deepsource_many_vuln.json")["dep-0002"]
        self.assertLessEqual(abs((finding.date - datetime.now(tz=UTC).date()).days), 1)

    def test_both_shapes_import_together(self):
        findings = self.parse("deepsource_many_vuln.json")
        self.assertEqual(9, len(findings))
        self.assertEqual(5, sum(1 for f in findings if f.unique_id_from_tool.startswith("occ-")))
        self.assertEqual(4, sum(1 for f in findings if f.unique_id_from_tool.startswith("dep-")))

    def test_a_bare_array_is_classified_per_entry(self):
        """
        A bare array can hold either shape, so each entry is judged on whether it has an advisory.

        Assuming a whole file is one shape would silently mis-map a mixed export.
        """
        report = io.StringIO(json.dumps([
            {"id": "occ-1", "path": "a.py", "beginLine": 1,
             "issue": {"shortcode": "PY-1", "title": "An issue",
                       "category": "SECURITY", "severity": "MAJOR"}},
            {"id": "dep-1", "vulnerability": {"identifier": "CVE-2000-0001", "cvssV3BaseScore": 5.0},
             "package": {"name": "p"}, "packageVersion": {"version": "1"}},
        ]))
        findings = {f.unique_id_from_tool: f for f in DeepSourceParser().get_findings(report, Test())}
        self.assertEqual("High", findings["occ-1"].severity)
        self.assertEqual("Medium", findings["dep-1"].severity)
        self.assertEqual("CVE-2000-0001 - p (1)", findings["dep-1"].title)

    def test_a_repeated_id_collapses(self):
        occurrence = {"id": "same", "path": "a.py", "beginLine": 1,
                      "issue": {"shortcode": "PY-1", "category": "SECURITY", "severity": "MAJOR"}}
        report = io.StringIO(json.dumps({"occurrences": [occurrence, occurrence]}))
        self.assertEqual(1, len(list(DeepSourceParser().get_findings(report, Test()))))

    def test_an_export_with_no_run_still_dates_the_findings(self):
        report = io.StringIO(json.dumps({"occurrences": [
            {"id": "o1", "path": "a.py", "beginLine": 1,
             "issue": {"shortcode": "PY-1", "category": "SECURITY", "severity": "MAJOR"}},
        ]}))
        finding = list(DeepSourceParser().get_findings(report, Test()))[0]
        self.assertLessEqual(abs((finding.date - datetime.now(tz=UTC).date()).days), 1)

    def test_an_unexpected_shape_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(DeepSourceParser().get_findings(io.StringIO('"nope"'), Test()))
        self.assertIn("occurrences", str(raised.exception))
