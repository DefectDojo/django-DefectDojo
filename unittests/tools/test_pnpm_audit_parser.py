import io
import json

from dojo.models import Finding, Test
from dojo.tools.pnpm_audit.parser import PnpmAuditParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestPnpmAuditParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("pnpm_audit") / filename).open(encoding="utf-8") as file:
            return list(PnpmAuditParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = PnpmAuditParser()
        self.assertEqual(["pnpm Audit Scan"], parser.get_scan_types())
        self.assertEqual("pnpm Audit Scan", parser.get_label_for_scan_types("pnpm Audit Scan"))
        self.assertIn("npm v6", parser.get_description_for_scan_types("pnpm Audit Scan"))

    def test_no_vuln(self):
        """A clean audit reports an empty advisories object plus a zeroed metadata block."""
        self.assertEqual(0, len(self.parse("pnpm_audit_no_vuln.json")))

    def test_one_vuln(self):
        """One declared dependency, but minimist 1.2.0 carries two separate advisories."""
        self.assertEqual(2, len(self.parse("pnpm_audit_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `pnpm audit --json` run against pinned versions."""
        findings = self.parse("pnpm_audit_one_vuln.json")
        finding = next(f for f in findings if f.severity == "Medium")

        self.assertEqual("minimist: Prototype Pollution in minimist", finding.title)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("minimist", finding.component_name)
        self.assertEqual("1.2.0", finding.component_version)
        self.assertEqual("GHSA-vh95-rmgr-6w4m", finding.vuln_id_from_tool)
        self.assertEqual(["GHSA-vh95-rmgr-6w4m"], finding.unsaved_vulnerability_ids)
        self.assertEqual("https://github.com/advisories/GHSA-vh95-rmgr-6w4m", finding.references)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

        self.assertIn("**Vulnerable versions:** >=1.0.0 <1.2.3", finding.description)
        self.assertIn("**Patched versions:** >=1.2.3", finding.description)
        self.assertIn("**Dependency paths:** .>minimist", finding.description)
        self.assertEqual("Upgrade minimist to >=1.2.3.", finding.mitigation)

    def test_the_cwe_string_becomes_a_number(self):
        """The advisory reports "CWE-1321"; DefectDojo's cwe field is an integer."""
        finding = next(
            f for f in self.parse("pnpm_audit_one_vuln.json") if f.component_name == "minimist"
        )
        self.assertEqual(1321, finding.cwe)

    def test_many_vuln(self):
        findings = self.parse("pnpm_audit_many_vuln.json")
        self.assertEqual(43, len(findings))
        self.assertIn("axios", {finding.component_name for finding in findings})

    def test_severities_come_from_the_advisory(self):
        """Gate: real npm advisory severities across the whole range, with no Info padding."""
        severities = {finding.severity for finding in self.parse("pnpm_audit_many_vuln.json")}
        self.assertEqual({"Critical", "High", "Medium", "Low"}, severities)

    def test_no_cve_is_invented(self):
        """
        The pnpm report has no CVE field at all, only a GitHub advisory id.

        Every identifier attached must therefore be a GHSA, never a fabricated CVE.
        """
        for finding in self.parse("pnpm_audit_many_vuln.json"):
            for identifier in finding.unsaved_vulnerability_ids or []:
                self.assertTrue(identifier.startswith("GHSA-"), identifier)

    def test_one_advisory_matching_two_installed_versions_is_two_findings(self):
        """Each installed version is separately fixable, so each becomes its own finding."""
        report = io.StringIO(json.dumps({"advisories": {"1": {
            "id": 1, "module_name": "lodash", "title": "Prototype pollution",
            "severity": "high", "github_advisory_id": "GHSA-aaaa-bbbb-cccc",
            "patched_versions": ">=4.17.21",
            "findings": [{"version": "4.17.15", "paths": [".>lodash"]},
                         {"version": "4.17.11", "paths": [".>a>lodash"]}],
        }}}))
        findings = list(PnpmAuditParser().get_findings(report, Test()))
        self.assertEqual(2, len(findings))
        self.assertEqual({"4.17.15", "4.17.11"}, {f.component_version for f in findings})

    def test_an_advisory_with_no_findings_entry_still_imports(self):
        report = io.StringIO(json.dumps({"advisories": {"1": {
            "id": 1, "module_name": "lodash", "title": "Something", "severity": "low",
        }}}))
        findings = list(PnpmAuditParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertIsNone(findings[0].component_version)
        self.assertEqual("Low", findings[0].severity)

    def test_a_malformed_cwe_is_ignored_rather_than_guessed(self):
        report = io.StringIO(json.dumps({"advisories": {"1": {
            "id": 1, "module_name": "x", "title": "t", "severity": "low", "cwe": "not-a-cwe",
        }}}))
        self.assertIsNone(list(PnpmAuditParser().get_findings(report, Test()))[0].cwe)

    def test_the_numeric_id_is_used_when_there_is_no_ghsa(self):
        report = io.StringIO(json.dumps({"advisories": {"1090049": {
            "id": 1090049, "module_name": "x", "title": "t", "severity": "high",
        }}}))
        finding = list(PnpmAuditParser().get_findings(report, Test()))[0]
        self.assertEqual("1090049", finding.vuln_id_from_tool)
        self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_a_json_array_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(PnpmAuditParser().get_findings(io.StringIO("[]"), Test()))
        self.assertIn("advisories", str(raised.exception))
