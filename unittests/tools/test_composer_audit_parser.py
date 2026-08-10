import io

from dojo.models import Finding, Test
from dojo.tools.composer_audit.parser import ComposerAuditParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestComposerAuditParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("composer_audit") / filename).open(encoding="utf-8") as file:
            return list(ComposerAuditParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = ComposerAuditParser()
        self.assertEqual(["Composer Audit Scan"], parser.get_scan_types())
        self.assertEqual("Composer Audit Scan", parser.get_label_for_scan_types("Composer Audit Scan"))
        self.assertIn("composer audit", parser.get_description_for_scan_types("Composer Audit Scan"))

    def test_no_vuln(self):
        """A clean audit reports an empty advisories object rather than omitting the key."""
        self.assertEqual(0, len(self.parse("composer_audit_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("composer_audit_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `composer audit --format=json --locked` run."""
        findings = self.parse("composer_audit_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual(
            "league/flysystem: TOCTOU Race Condition enabling remote code execution",
            finding.title,
        )
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("league/flysystem", finding.component_name)
        self.assertEqual("PKSA-pwh8-d4fr-nywn", finding.vuln_id_from_tool)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(
            "https://github.com/thephpleague/flysystem/security/advisories/GHSA-9f46-5r25-5wfm",
            finding.references,
        )

        self.assertIn("**Affected versions:** <1.1.4|>=2.0.0,<2.1.1", finding.description)
        self.assertIn("**Reported:** 2021-06-23", finding.description)
        self.assertIn("outside the affected range", finding.mitigation)

    def test_both_the_cve_and_the_ghsa_are_reported(self):
        """
        The advisory carries a CVE field AND a GitHub id under "sources".

        Both are public identifiers for the same flaw, so both are attached.
        """
        finding = self.parse("composer_audit_one_vuln.json")[0]
        self.assertEqual(["CVE-2021-32708", "GHSA-9f46-5r25-5wfm"], finding.unsaved_vulnerability_ids)

    def test_a_null_cve_falls_back_to_the_github_id(self):
        """
        A composer advisory often reports "cve": null while still naming a GitHub advisory.

        Without the fallback those findings would carry no public identifier at all.
        """
        report = io.StringIO(
            '{"advisories": {"vendor/pkg": [{"advisoryId": "PKSA-aaaa-bbbb-cccc",'
            ' "packageName": "vendor/pkg", "title": "Something", "cve": null,'
            ' "severity": "high", "sources": [{"name": "GitHub", "remoteId": "GHSA-1111-2222-3333"}]}]}}',
        )
        finding = list(ComposerAuditParser().get_findings(report, Test()))[0]
        self.assertEqual(["GHSA-1111-2222-3333"], finding.unsaved_vulnerability_ids)

    def test_many_vuln(self):
        """One package can carry several advisories, and each is separately fixable."""
        findings = self.parse("composer_audit_many_vuln.json")
        self.assertEqual(16, len(findings))
        self.assertEqual(
            {"guzzlehttp/guzzle", "guzzlehttp/psr7"},
            {finding.component_name for finding in findings},
        )

    def test_severities_come_from_the_advisory(self):
        """Gate: these are real vendor severities, not a fixed level chosen by the parser."""
        severities = {finding.severity for finding in self.parse("composer_audit_many_vuln.json")}
        self.assertEqual({"Medium", "High"}, severities)
        self.assertNotIn("Info", severities)

    def test_component_version_is_not_invented(self):
        """
        The report names the affected version RANGE, never the installed version.

        The installed version lives in composer.lock, not the report, so the field is left unset
        rather than filled with the range.
        """
        for finding in self.parse("composer_audit_many_vuln.json"):
            self.assertIsNone(finding.component_version)

    def test_an_advisory_with_no_severity_takes_the_default(self):
        report = io.StringIO(
            '{"advisories": {"vendor/pkg": [{"advisoryId": "PKSA-x", "packageName": "vendor/pkg",'
            ' "title": "No severity recorded"}]}}',
        )
        finding = list(ComposerAuditParser().get_findings(report, Test()))[0]
        self.assertEqual("Medium", finding.severity)

    def test_empty_advisories_object(self):
        report = io.StringIO('{"advisories": {}, "abandoned": [], "filter": []}')
        self.assertEqual([], list(ComposerAuditParser().get_findings(report, Test())))

    def test_a_json_array_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(ComposerAuditParser().get_findings(io.StringIO("[]"), Test()))
        self.assertIn("advisories", str(raised.exception))
