import io
import json

from dojo.models import Test
from dojo.tools.uv_audit.parser import UvAuditParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestUvAuditParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("uv_audit") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = UvAuditParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("uv_audit") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = UvAuditParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("click: PYSEC-2026-2132", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("PYSEC-2026-2132", finding.vuln_id_from_tool)
            self.assertEqual("click", finding.component_name)
            self.assertEqual("8.1.8", finding.component_version)
            self.assertEqual("Upgrade click to 8.3.3.", finding.mitigation)
            self.assertIn("**uv audit schema version:** preview", finding.description)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

            with self.subTest("the GHSA alias is not recorded as a CVE"):
                self.assertEqual(["CVE-2026-7246"], finding.unsaved_vulnerability_ids)
                self.assertIn("GHSA-47fr-3ffg-hgmw", finding.description)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("uv_audit") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = UvAuditParser().get_findings(testfile, Test())
            self.assertEqual(6, len(findings))

            with self.subTest("uv audit reports no severity, so every finding is Medium"):
                self.assertEqual({"Medium"}, {f.severity for f in findings})

            with self.subTest("each advisory is attributed to its own package and version"):
                self.assertEqual(
                    {"click", "flask", "idna", "jinja2", "requests", "urllib3"},
                    {f.component_name for f in findings},
                )
                for finding in findings:
                    self.assertIsNotNone(finding.component_version)

            with self.subTest("advisory ids are unique and each carries a fix"):
                self.assertEqual(6, len({f.vuln_id_from_tool for f in findings}))
                for finding in findings:
                    self.assertIn("Upgrade", finding.mitigation)

    def test_advisory_reported_directly_as_a_cve(self):
        """Some databases key the advisory by its CVE rather than listing it as an alias."""
        report = {
            "schema": {"version": "preview"},
            "vulnerabilities": [{
                "dependency": {"name": "example-pkg", "version": "1.0.0"},
                "id": "CVE-2026-0001", "display_id": "CVE-2026-0001",
                "aliases": ["GHSA-aaaa-bbbb-cccc"], "fix_versions": [],
            }],
        }
        findings = UvAuditParser().get_findings(io.StringIO(json.dumps(report)), Test())
        self.assertEqual(["CVE-2026-0001"], findings[0].unsaved_vulnerability_ids)
        self.assertIsNone(findings[0].mitigation)
