import io
import json
from datetime import UTC, date, datetime

from dojo.models import Finding, Test
from dojo.tools.soos.parser import SoosParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSoosParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("soos") / filename
        with path.open(encoding="utf-8") as file:
            return list(SoosParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(SoosParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def issue(self, **overrides):
        row = {"id": "issue-1", "title": "An issue", "severity": "High", "scanType": "sca",
               "status": "Open"}
        row.update(overrides)
        return {"entries": [row]}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """Must equal the SOOS connector's ScanTypeName verbatim."""
        parser = SoosParser()
        self.assertEqual(["SOOS - Connectors Import"], parser.get_scan_types())
        self.assertEqual("SOOS - Connectors Import",
                         parser.get_label_for_scan_types("SOOS - Connectors Import"))

    def test_this_scan_type_has_no_curated_dedupe_fields(self):
        """No hash-field list to copy, so it uses DefectDojo's default algorithm - as the connector does."""
        self.assertFalse(hasattr(SoosParser(), "get_dedupe_fields"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("soos_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("soos_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring ConvertFinding in the connector's finding_converter."""
        findings = self.parse("soos_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Prototype pollution in the example utility library", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("issue-0001", finding.unique_id_from_tool)
        self.assertEqual("CVE-2000-0001", finding.vuln_id_from_tool)
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual(1321, finding.cwe)
        self.assertEqual("example-utils", finding.component_name)
        self.assertEqual("4.17.20", finding.component_version)
        self.assertEqual("package-lock.json", finding.file_path)
        self.assertIsNone(finding.line)
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", finding.cvssv3)
        self.assertEqual("https://example.com/advisories/CVE-2000-0001", finding.references)
        self.assertEqual("Upgrade example-utils to 4.17.21 or later.", finding.mitigation)
        self.assertEqual(date(2024, 6, 2), finding.date)
        self.assertTrue(finding.active)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(["sca"], finding.unsaved_tags)
        self.assertEqual("A crafted key allows an attacker to modify the object prototype.",
                         finding.description)

    def test_many_vuln(self):
        self.assertEqual(7, len(self.parse("soos_many_vuln.json")))

    def test_the_scan_type_decides_static_versus_dynamic_per_issue(self):
        """
        SOOS puts SCA, SAST, container, SBOM and DAST behind ONE API and stamps each issue.

        So this is decided per issue rather than for the file - only DAST exercises anything.
        """
        findings = self.by_uid("soos_many_vuln.json")
        for uid, static in (("issue-0001", True), ("issue-0002", False), ("issue-0003", True),
                            ("issue-0004", True), ("issue-0005", True), ("issue-0007", False)):
            with self.subTest(uid=uid):
                self.assertEqual(static, findings[uid].static_finding)
                self.assertEqual(not static, findings[uid].dynamic_finding)

    def test_scan_types(self):
        for scan_type, static in (("sca", True), ("sast", True), ("csa", True), ("sbom", True),
                                  ("dast", False), ("SCA", True), ("", False)):
            with self.subTest(scan_type=scan_type):
                findings = self.parse_string(self.issue(scanType=scan_type))
                self.assertEqual(static, findings[0].static_finding)

    def test_an_unrecognised_scan_type_arrives_as_dynamic(self):
        """
        The connector reads its lookup table with a Go map access, which yields false for a missing key.

        Mirrored rather than corrected - a new SOOS scan type would arrive as dynamic, which is worth
        raising on the connector side rather than diverging here.
        """
        finding = self.by_uid("soos_many_vuln.json")["issue-0006"]
        self.assertFalse(finding.static_finding)
        self.assertTrue(finding.dynamic_finding)
        self.assertEqual(["iac"], finding.unsaved_tags)

    def test_unknown_is_a_real_soos_severity_and_grades_as_info(self):
        """A finding SOOS could not grade is still a finding, so it is not dropped."""
        finding = self.by_uid("soos_many_vuln.json")["issue-0005"]
        self.assertEqual("Info", finding.severity)

    def test_severity_words(self):
        for label, expected in (("Critical", "Critical"), ("High", "High"), ("Medium", "Medium"),
                                ("Low", "Low"), ("Info", "Info"), ("Unknown", "Info"),
                                ("critical", "Critical"), ("a word it does not use", "Info"),
                                ("", "Info")):
            with self.subTest(label=label):
                findings = self.parse_string(self.issue(severity=label))
                self.assertEqual(expected, findings[0].severity)

    def test_the_three_kinds_of_dismissal_are_kept_apart(self):
        """
        A false positive was never real, an accepted risk is real and signed off, and a resolved issue
        is dealt with.

        Collapsing them would lose the distinction a reviewer already made on the SOOS side.
        """
        findings = self.by_uid("soos_many_vuln.json")

        false_positive = findings["issue-0003"]
        self.assertFalse(false_positive.active)
        self.assertTrue(false_positive.false_p)
        self.assertFalse(false_positive.risk_accepted)
        self.assertFalse(false_positive.is_mitigated)

        accepted = findings["issue-0004"]
        self.assertFalse(accepted.active)
        self.assertTrue(accepted.risk_accepted)
        self.assertFalse(accepted.false_p)

        resolved = findings["issue-0005"]
        self.assertFalse(resolved.active)
        self.assertTrue(resolved.is_mitigated)
        self.assertFalse(resolved.risk_accepted)

    def test_statuses(self):
        cases = (
            ("Open", "active"), ("", "active"), ("Something new", "active"),
            ("False positive", "false_p"), ("falsepositive", "false_p"),
            ("false_positive", "false_p"),
            ("Accepted", "risk_accepted"),
            ("Ignored", "is_mitigated"), ("Dismissed", "is_mitigated"),
            ("Resolved", "is_mitigated"), ("Fixed", "is_mitigated"),
        )
        for status, expected in cases:
            with self.subTest(status=status):
                finding = self.parse_string(self.issue(status=status))[0]
                if expected == "active":
                    self.assertTrue(finding.active)
                else:
                    self.assertFalse(finding.active)
                    self.assertTrue(getattr(finding, expected))

    def test_a_status_with_spaces_is_normalised(self):
        """SOOS writes "False positive"; the connector strips the spaces before matching."""
        for status in ("False positive", "FALSE POSITIVE", " false  positive "):
            with self.subTest(status=status):
                findings = self.parse_string(self.issue(status=status))
                self.assertTrue(findings[0].false_p)

    def test_a_dast_url_becomes_an_endpoint(self):
        finding = self.by_uid("soos_many_vuln.json")["issue-0002"]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("app.example.com", locations[0].host)
        self.assertEqual("https", locations[0].protocol)
        self.assertEqual("search", locations[0].path)
        self.assertEqual("q=1", locations[0].query)

    def test_a_source_finding_has_a_file_path_and_no_endpoint(self):
        finding = self.by_uid("soos_many_vuln.json")["issue-0003"]
        self.assertEqual("src/generic/config.py", finding.file_path)
        self.assertEqual(42, finding.line)
        self.assertEqual(0, len(self.get_unsaved_locations(finding)))

    def test_a_url_defectdojo_would_reject_adds_no_endpoint(self):
        """
        A bad host makes Endpoint.clean() raise, which fails the WHOLE import.

        Declining to build the endpoint keeps the rest of the file importable.
        """
        finding = self.by_uid("soos_many_vuln.json")["issue-0007"]
        self.assertEqual(0, len(self.get_unsaved_locations(finding)))
        self.assertFalse(finding.active)

    def test_the_mitigation_prefers_the_remediation_text(self):
        findings = self.by_uid("soos_many_vuln.json")
        self.assertEqual("Move the value into an environment variable.",
                         findings["issue-0003"].mitigation)

    def test_the_mitigation_names_the_package_and_the_fixed_version(self):
        findings = self.by_uid("soos_many_vuln.json")
        self.assertEqual("Upgrade example-base to 3.20 or later.", findings["issue-0004"].mitigation)

    def test_the_mitigation_omits_the_package_when_soos_did_not_name_one(self):
        findings = self.parse_string(self.issue(packageName="", fixedVersion="2.0.0"))
        self.assertEqual("Upgrade to 2.0.0 or later.", findings[0].mitigation)

    def test_no_remediation_and_no_fixed_version_leaves_the_mitigation_unset(self):
        findings = self.by_uid("soos_many_vuln.json")
        self.assertIsNone(findings["issue-0002"].mitigation)

    def test_an_issue_with_no_prose_says_which_scan_reported_it(self):
        """An empty body would read as though the data had been lost in transit."""
        finding = self.by_uid("soos_many_vuln.json")["issue-0002"]
        self.assertEqual("Reported by the SOOS dast scan.", finding.description)

    def test_an_issue_with_no_prose_and_no_scan_type_still_says_something(self):
        findings = self.parse_string(self.issue(description="", scanType=""))
        self.assertEqual("Reported by SOOS.", findings[0].description)

    def test_cwe_forms(self):
        for value, expected in (("CWE-79", 79), ("79", 79), ("cwe-79", 79), ("not a cwe", 0),
                                ("", 0)):
            with self.subTest(value=value):
                findings = self.parse_string(self.issue(cwe=value))
                self.assertEqual(expected, findings[0].cwe)

    def test_a_bare_cwe_number_and_an_unparseable_one(self):
        findings = self.by_uid("soos_many_vuln.json")
        self.assertEqual(79, findings["issue-0002"].cwe)
        self.assertEqual(0, findings["issue-0003"].cwe)

    def test_an_issue_with_no_cve_carries_no_vulnerability_id(self):
        findings = self.by_uid("soos_many_vuln.json")
        self.assertIsNone(findings["issue-0002"].vuln_id_from_tool)
        self.assertIsNone(findings["issue-0002"].unsaved_vulnerability_ids)

    def test_a_line_of_zero_is_not_recorded(self):
        finding = self.by_uid("soos_many_vuln.json")["issue-0001"]
        self.assertIsNone(finding.line)

    def test_an_unparseable_first_detected_leaves_the_date_alone(self):
        finding = self.by_uid("soos_many_vuln.json")["issue-0006"]
        self.assertEqual(datetime.now(tz=UTC).date(), finding.date)

    def test_export_shapes(self):
        row = {"id": "issue-1", "title": "An issue", "severity": "Low", "scanType": "sca"}
        for payload in ([row], {"entries": [row]}, {"items": [row]}, {"issues": [row]},
                        {"data": [row]}, {"results": [row]}):
            with self.subTest(shape=str(payload)[:22]):
                self.assertEqual(1, len(self.parse_string(payload)))

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("SOOS", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("entries", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"entries": [
            "not an object",
            None,
            {"id": "issue-9", "title": "An issue", "severity": "Low", "scanType": "sca",
             "cvssScore": "not a number", "line": "not a line"},
        ]})
        self.assertEqual(1, len(findings))
        self.assertEqual("issue-9", findings[0].unique_id_from_tool)
        self.assertEqual(0.0, findings[0].cvssv3_score)
        self.assertIsNone(findings[0].line)

    def test_severity_is_always_a_known_value(self):
        for filename in ("soos_many_vuln.json", "soos_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
