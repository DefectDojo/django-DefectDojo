import io
import json

from dojo.models import Finding, Test
from dojo.tools.mix_audit.parser import MixAuditParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestMixAuditParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("mix_audit") / filename).open(encoding="utf-8") as file:
            return list(MixAuditParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = MixAuditParser()
        self.assertEqual(["Mix Audit Scan"], parser.get_scan_types())
        self.assertEqual("Mix Audit Scan", parser.get_label_for_scan_types("Mix Audit Scan"))
        self.assertIn("mix deps.audit", parser.get_description_for_scan_types("Mix Audit Scan"))

    def test_no_vuln(self):
        """A clean audit reports pass=true and an empty vulnerabilities list."""
        content = (get_unit_tests_scans_path("mix_audit")
                   / "mix_audit_no_vuln.json").read_text(encoding="utf-8")
        self.assertIn('"pass":true', content.replace(" ", ""))

        self.assertEqual(0, len(self.parse("mix_audit_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("mix_audit_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `mix deps.audit --format json` run."""
        findings = self.parse("mix_audit_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("sweet_xml: Inline DTD allows XML bomb attack", finding.title)
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("sweet_xml", finding.component_name)
        self.assertEqual("0.6.5", finding.component_version)
        self.assertEqual("GHSA-qpmc-wprv-x746", finding.vuln_id_from_tool)
        self.assertEqual(["GHSA-qpmc-wprv-x746"], finding.unsaved_vulnerability_ids)
        self.assertEqual("https://github.com/advisories/GHSA-qpmc-wprv-x746", finding.references)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

        self.assertIn("denial of service", finding.description)
        self.assertIn("**Installed version:** 0.6.5", finding.description)
        self.assertIn("**First patched versions:**", finding.description)
        self.assertEqual("Upgrade sweet_xml to 0.7.0 or later.", finding.mitigation)

    def test_the_disclosure_date_is_kept(self):
        self.assertIsNotNone(self.parse("mix_audit_one_vuln.json")[0].publish_date)

    def test_many_vuln(self):
        findings = self.parse("mix_audit_many_vuln.json")
        self.assertEqual(2, len(findings))
        self.assertEqual({"plug", "sweet_xml"}, {f.component_name for f in findings})

    def test_severities_come_from_the_advisory(self):
        """Gate: severities are the advisory's own, and none is Info."""
        severities = {f.severity for f in self.parse("mix_audit_many_vuln.json")}
        self.assertEqual({"High"}, severities)
        self.assertNotIn("Info", severities)

    def test_no_cve_is_invented(self):
        """
        The Elixir advisory data has no CVE field, only a GHSA id.

        So every identifier attached must be a GHSA rather than a fabricated CVE.
        """
        for finding in self.parse("mix_audit_many_vuln.json"):
            for identifier in finding.unsaved_vulnerability_ids or []:
                self.assertTrue(identifier.startswith("GHSA-"), identifier)

    def test_an_advisory_with_no_severity_takes_the_default(self):
        report = io.StringIO(json.dumps({"pass": False, "vulnerabilities": [{
            "dependency": {"package": "pkg", "version": "1.0.0"},
            "advisory": {"id": "GHSA-aaaa-bbbb-cccc", "title": "No severity recorded"},
        }]}))
        finding = list(MixAuditParser().get_findings(report, Test()))[0]
        self.assertEqual("Medium", finding.severity)

    def test_no_patched_version_changes_the_mitigation(self):
        report = io.StringIO(json.dumps({"pass": False, "vulnerabilities": [{
            "dependency": {"package": "pkg", "version": "1.0.0"},
            "advisory": {"id": "GHSA-x", "title": "t", "severity": "low"},
        }]}))
        finding = list(MixAuditParser().get_findings(report, Test()))[0]
        self.assertEqual("Upgrade pkg to a version that is not affected by this advisory.", finding.mitigation)

    def test_the_same_advisory_on_two_versions_stays_two_findings(self):
        report = io.StringIO(json.dumps({"pass": False, "vulnerabilities": [
            {"dependency": {"package": "pkg", "version": "1.0.0"},
             "advisory": {"id": "GHSA-x", "title": "t", "severity": "high"}},
            {"dependency": {"package": "pkg", "version": "2.0.0"},
             "advisory": {"id": "GHSA-x", "title": "t", "severity": "high"}},
        ]}))
        self.assertEqual(2, len(list(MixAuditParser().get_findings(report, Test()))))

    def test_a_json_array_is_rejected_and_the_message_names_the_compile_noise_trap(self):
        """
        The FIRST `mix deps.audit` in a clean checkout prints compiler output before the JSON.

        That is the likeliest reason a user's file will not parse, so the error says so.
        """
        with self.assertRaises(TypeError) as raised:
            list(MixAuditParser().get_findings(io.StringIO("[]"), Test()))
        message = str(raised.exception)
        self.assertIn("vulnerabilities", message)
        self.assertIn("second run", message)
