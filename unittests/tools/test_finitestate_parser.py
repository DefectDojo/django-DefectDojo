import io
import json
from datetime import UTC, date, datetime

from dojo.models import Finding, Test
from dojo.tools.finitestate.parser import FinitestateParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestFinitestateParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("finitestate") / filename
        with path.open(encoding="utf-8") as file:
            return list(FinitestateParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(FinitestateParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def row(self, **overrides):
        row = {"id": "finding-1", "title": "A finding", "severity": "high"}
        row.update(overrides)
        return {"data": {"allFindings": [row]}}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """Must equal the Finite State connector's ScanTypeName verbatim."""
        parser = FinitestateParser()
        self.assertEqual(["Finite State - Connectors Import"], parser.get_scan_types())
        self.assertEqual("Finite State - Connectors Import",
                         parser.get_label_for_scan_types("Finite State - Connectors Import"))

    def test_this_scan_type_has_no_curated_dedupe_fields(self):
        """
        Finite State has no hash-field list to copy, so it uses DefectDojo's default algorithm.

        That is what the connector's own findings already do. Choosing hash fields here would change
        how those findings deduplicate too, which is not this parser's decision to make.
        """
        self.assertFalse(hasattr(FinitestateParser(), "get_dedupe_fields"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("finitestate_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("finitestate_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring ConvertFinding in the connector's finding_converter."""
        findings = self.parse("finitestate_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Outdated TLS library in the firmware image", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("finding-0001", finding.unique_id_from_tool)
        self.assertEqual("FS-2024-0001", finding.vuln_id_from_tool)
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual(787, finding.cwe)
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", finding.cvssv3)
        self.assertEqual(0.42, finding.epss_score)
        self.assertEqual(0.97, finding.epss_percentile)
        self.assertEqual("example-tls", finding.component_name)
        self.assertEqual("1.0.2k", finding.component_version)
        self.assertEqual(date(2024, 6, 2), finding.date)
        self.assertTrue(finding.active)
        self.assertFalse(finding.out_of_scope)
        self.assertFalse(finding.false_p)
        self.assertFalse(finding.is_mitigated)
        self.assertFalse(finding.under_review)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(
            ["firmware-build:1.4.0", "SBOM", "Known vulnerability", "BINARY_ANALYSIS",
             "Binary Analysis", "weaponized", "exploited-in-the-wild"],
            finding.unsaved_tags,
        )
        self.assertEqual(
            "The image bundles a TLS library with known remote code execution flaws.\n\n"
            "**Asset:** Generic Router\n"
            "**Firmware build:** 1.4.0\n"
            "**Build relative risk score:** 2.5\n"
            "**Category:** SBOM\n"
            "**Origin:** FIRMWARE\n"
            "**VEX status:** AFFECTED\n"
            "**VEX comment:** Confirmed present in the shipping build.\n"
            "**Risk score:** 87.5\n",
            finding.description,
        )

    def test_the_description_keeps_its_trailing_newline(self):
        """
        The connector does not trim the description it builds.

        Reproduced rather than tidied, so a file import and an API sync render identically.
        """
        finding = self.parse("finitestate_one_vuln.json")[0]
        self.assertTrue(finding.description.endswith("\n"))

    def test_many_vuln(self):
        self.assertEqual(6, len(self.parse("finitestate_many_vuln.json")))

    def test_a_not_affected_finding_is_out_of_scope_and_not_active(self):
        """
        NOT_AFFECTED is a product team asserting the vulnerability does not apply to this build.

        Leaving it active would put an answered question back in the queue on every import.
        """
        finding = self.by_uid("finitestate_many_vuln.json")["finding-0002"]
        self.assertFalse(finding.active)
        self.assertTrue(finding.out_of_scope)

    def test_a_not_affected_finding_is_a_false_positive_only_when_the_code_is_absent(self):
        """
        "Vulnerable code not present" means there was never anything to fix - a false positive.

        "Inline mitigations already exist" means the flaw is real but handled, which is out of scope
        and NOT a false positive. The distinction matters for metrics.
        """
        findings = self.by_uid("finitestate_many_vuln.json")
        absent = findings["finding-0002"]
        self.assertTrue(absent.false_p)
        self.assertTrue(absent.out_of_scope)

        mitigated_in_place = findings["finding-0003"]
        self.assertTrue(mitigated_in_place.out_of_scope)
        self.assertFalse(mitigated_in_place.false_p)

    def test_every_absence_justification_is_a_false_positive(self):
        for justification in ("COMPONENT_NOT_PRESENT", "VULNERABLE_CODE_NOT_PRESENT",
                              "VULNERABLE_CODE_NOT_IN_EXECUTE_PATH"):
            with self.subTest(justification=justification):
                findings = self.parse_string(self.row(currentStatus={
                    "status": "NOT_AFFECTED", "justification": justification}))
                self.assertTrue(findings[0].false_p)

    def test_a_fixed_finding_is_mitigated_and_records_when(self):
        finding = self.by_uid("finitestate_many_vuln.json")["finding-0004"]
        self.assertFalse(finding.active)
        self.assertTrue(finding.is_mitigated)
        self.assertEqual(datetime(2024, 6, 5, 14, 30), finding.mitigated.replace(tzinfo=None))

    def test_an_under_investigation_finding_stays_active_and_is_under_review(self):
        """Nobody has ruled it out yet, so it stays in the queue - flagged as being looked at."""
        finding = self.by_uid("finitestate_many_vuln.json")["finding-0005"]
        self.assertTrue(finding.active)
        self.assertTrue(finding.under_review)
        self.assertFalse(finding.out_of_scope)

    def test_affected_and_unrecognised_statuses_stay_active(self):
        """
        Staying active is the safe direction to be wrong in.

        A finding wrongly left active gets triaged; one wrongly closed is never seen again.
        """
        for status in ("AFFECTED", "SOMETHING_NEW", "", "affected"):
            with self.subTest(status=status):
                findings = self.parse_string(self.row(currentStatus={"status": status}))
                self.assertTrue(findings[0].active)
                self.assertFalse(findings[0].out_of_scope)
                self.assertFalse(findings[0].is_mitigated)

    def test_a_finding_with_no_status_block_stands_as_reported(self):
        finding = self.by_uid("finitestate_many_vuln.json")["finding-0006"]
        self.assertTrue(finding.active)
        self.assertFalse(finding.out_of_scope)
        self.assertNotIn("**VEX status:**", finding.description)

    def test_the_highest_epss_across_the_findings_cves_is_used(self):
        """
        EPSS is per-CVE, and the finding's real exploitation likelihood is the highest of them.

        The percentile travels with the score it belongs to rather than being mixed in from another
        CVE - the fixture's lower-scoring CVE has a different percentile.
        """
        finding = self.by_uid("finitestate_many_vuln.json")["finding-0001"]
        self.assertEqual(0.62, finding.epss_score)
        self.assertEqual(0.99, finding.epss_percentile)

    def test_the_first_cve_vector_is_used_and_the_finding_score_wins(self):
        """The finding carries 9.8 while its second CVE scores 7.5; the finding's own score wins."""
        finding = self.by_uid("finitestate_many_vuln.json")["finding-0001"]
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertEqual("CVSS:3.1/AV:N", finding.cvssv3)

    def test_a_cve_base_score_is_the_fallback_when_the_finding_has_none(self):
        findings = self.parse_string(self.row(cvssScore=0, cves=[
            {"cveId": "CVE-2000-0001",
             "cvssBaseMetricV3": {"cvssv3": {"baseScore": 6.1, "vectorString": "CVSS:3.1/AV:N"}}},
        ]))
        self.assertEqual(6.1, findings[0].cvssv3_score)

    def test_severity_prefers_the_platform_severity_over_the_cvss_one(self):
        """The fixture's second finding is "high" with cvssSeverity "medium"."""
        finding = self.by_uid("finitestate_many_vuln.json")["finding-0002"]
        self.assertEqual("High", finding.severity)

    def test_the_cvss_severity_is_used_when_the_platform_severity_is_missing(self):
        finding = self.by_uid("finitestate_many_vuln.json")["finding-0005"]
        self.assertEqual("High", finding.severity)

    def test_unknown_is_a_recognised_word_and_does_not_fall_through(self):
        """
        "unknown" and "none" are values Finite State actually uses, and both mean Info.

        So a finding graded "unknown" is Info even when its CVSS severity says Critical - the
        fall-through only happens for a word the platform does not use at all. Treating "unknown" as
        missing would silently upgrade every unscored finding.
        """
        findings = self.parse_string(self.row(severity="unknown", cvssSeverity="critical"))
        self.assertEqual("Info", findings[0].severity)
        findings = self.parse_string(self.row(severity="none", cvssSeverity="critical"))
        self.assertEqual("Info", findings[0].severity)
        findings = self.parse_string(self.row(severity="a word it does not use",
                                              cvssSeverity="critical"))
        self.assertEqual("Critical", findings[0].severity)

    def test_severity_words(self):
        for label, expected in (("critical", "Critical"), ("high", "High"), ("medium", "Medium"),
                                ("low", "Low"), ("info", "Info"), ("none", "Info"),
                                ("unknown", "Info"), ("CRITICAL", "Critical")):
            with self.subTest(label=label):
                findings = self.parse_string(self.row(severity=label))
                self.assertEqual(expected, findings[0].severity)

    def test_an_unrecognised_severity_in_both_fields_is_info(self):
        """
        Inventing a grade for a word the platform does not use would be worse than under-reporting.

        The connector logs a warning and falls back to Info; this does the same silently.
        """
        finding = self.by_uid("finitestate_many_vuln.json")["finding-0006"]
        self.assertEqual("Info", finding.severity)

    def test_the_first_parseable_cwe_wins_and_a_bare_number_is_accepted(self):
        """The fixture's first CWE is not a number at all, so the second is used."""
        finding = self.by_uid("finitestate_many_vuln.json")["finding-0002"]
        self.assertEqual(89, finding.cwe)

    def test_cwe_forms(self):
        for value, expected in (("CWE-79", 79), ("79", 79), ("cwe-79", 79), ("not a cwe", 0),
                                ("", 0)):
            with self.subTest(value=value):
                findings = self.parse_string(self.row(cwes=[{"cweId": value}]))
                self.assertEqual(expected, findings[0].cwe)

    def test_a_finding_with_no_cwe_has_zero(self):
        finding = self.by_uid("finitestate_many_vuln.json")["finding-0004"]
        self.assertEqual(0, finding.cwe)

    def test_the_first_affected_component_is_the_component(self):
        findings = self.by_uid("finitestate_many_vuln.json")
        self.assertEqual("example-tls", findings["finding-0001"].component_name)
        self.assertEqual("1.0.2k", findings["finding-0001"].component_version)
        self.assertIsNone(findings["finding-0005"].component_name)

    def test_the_build_tag_names_the_firmware_the_finding_belongs_to(self):
        """
        Several builds of one product land in the same DefectDojo product.

        The tag is what lets a reader tell which firmware a finding is from without opening it.
        """
        finding = self.by_uid("finitestate_many_vuln.json")["finding-0001"]
        self.assertIn("firmware-build:1.4.0", finding.unsaved_tags)

    def test_the_build_tag_falls_back_to_the_build_id(self):
        payload = self.row()
        payload["assetVersion"] = {"id": "ver-0009", "name": ""}
        findings = self.parse_string(payload)
        self.assertIn("firmware-build:ver-0009", findings[0].unsaved_tags)

    def test_a_regression_is_tagged(self):
        findings = self.by_uid("finitestate_many_vuln.json")
        self.assertIn("regression", findings["finding-0004"].unsaved_tags)
        self.assertNotIn("regression", findings["finding-0001"].unsaved_tags)

    def test_exploit_intel_is_tagged_from_any_of_the_findings_cves(self):
        """The fixture's first CVE has neither flag; its second has both."""
        finding = self.by_uid("finitestate_many_vuln.json")["finding-0001"]
        self.assertIn("weaponized", finding.unsaved_tags)
        self.assertIn("exploited-in-the-wild", finding.unsaved_tags)

    def test_tags_are_deduplicated(self):
        payload = self.row(category="SBOM", subcategory="SBOM", sourceTypes=["SBOM"],
                           test={"tools": [{"name": "SBOM"}, {"name": "SBOM"}]})
        findings = self.parse_string(payload)
        self.assertEqual(["SBOM"], findings[0].unsaved_tags)

    def test_the_build_context_may_be_stated_once_for_the_file_or_per_row(self):
        """
        One export is one firmware build, so the context is normally stated once.

        A row carrying its own overrides it, for an export that repeats the context per finding.
        """
        payload = {"asset": {"name": "Generic Router"},
                   "assetVersion": {"name": "1.4.0"},
                   "data": {"allFindings": [
                       {"id": "a", "title": "Uses the file context", "severity": "low"},
                       {"id": "b", "title": "Carries its own", "severity": "low",
                        "asset": {"name": "Generic Switch"}, "assetVersion": {"name": "9.9.9"}},
                   ]}}
        findings = {finding.unique_id_from_tool: finding for finding in self.parse_string(payload)}
        self.assertIn("**Asset:** Generic Router", findings["a"].description)
        self.assertIn("firmware-build:1.4.0", findings["a"].unsaved_tags)
        self.assertIn("**Asset:** Generic Switch", findings["b"].description)
        self.assertIn("firmware-build:9.9.9", findings["b"].unsaved_tags)

    def test_an_export_with_no_build_context_still_imports(self):
        findings = self.parse("finitestate_findings_only.json")
        self.assertEqual(1, len(findings))
        self.assertEqual("finding-0010", findings[0].unique_id_from_tool)
        self.assertNotIn("**Asset:**", findings[0].description)
        self.assertNotIn("**Firmware build:**", findings[0].description)
        # The finding's own category still tags it; only the build tag is missing.
        self.assertEqual(["SBOM"], findings[0].unsaved_tags)
        self.assertFalse([tag for tag in findings[0].unsaved_tags if tag.startswith("firmware-build:")])

    def test_export_shapes(self):
        row = {"id": "finding-1", "title": "A finding", "severity": "low"}
        for payload in ([row], {"data": {"allFindings": [row]}}, {"allFindings": [row]},
                        {"findings": [row]}):
            with self.subTest(shape=str(payload)[:24]):
                self.assertEqual(1, len(self.parse_string(payload)))

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("Finite State", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("allFindings", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"data": {"allFindings": [
            "not an object",
            None,
            {"id": "finding-9", "title": "A finding", "severity": "low",
             "cwes": ["not an object", None], "cves": ["not an object", None],
             "affects": ["not an object"]},
        ]}})
        self.assertEqual(1, len(findings))
        self.assertEqual("finding-9", findings[0].unique_id_from_tool)
        self.assertEqual(0, findings[0].cwe)
        self.assertIsNone(findings[0].unsaved_vulnerability_ids)
        self.assertIsNone(findings[0].component_name)

    def test_a_risk_score_of_zero_is_not_reported(self):
        findings = self.by_uid("finitestate_many_vuln.json")
        self.assertIn("**Risk score:** 87.5", findings["finding-0001"].description)
        self.assertNotIn("**Risk score:**", findings["finding-0004"].description)

    def test_scores_render_without_a_trailing_zero(self):
        """The connector formats them in their shortest round-tripping form, so 3.0 is "3"."""
        payload = self.row(riskScore=3.0)
        payload["assetVersion"] = {"name": "1.0", "relativeRiskScore": 2.0}
        findings = self.parse_string(payload)
        self.assertIn("**Risk score:** 3\n", findings[0].description)
        self.assertIn("**Build relative risk score:** 2\n", findings[0].description)

    def test_an_unparseable_date_leaves_the_date_alone(self):
        finding = self.by_uid("finitestate_many_vuln.json")["finding-0006"]
        self.assertEqual(datetime.now(tz=UTC).date(), finding.date)

    def test_the_date_falls_back_to_when_the_finding_was_created(self):
        findings = self.by_uid("finitestate_many_vuln.json")
        self.assertEqual(date(2024, 6, 2), findings["finding-0001"].date)
        self.assertEqual(date(2024, 5, 20), findings["finding-0002"].date)

    def test_severity_is_always_a_known_value(self):
        for filename in ("finitestate_many_vuln.json", "finitestate_one_vuln.json",
                         "finitestate_findings_only.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
