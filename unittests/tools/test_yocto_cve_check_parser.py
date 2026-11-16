import io
import json

from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone

from dojo.importers.default_importer import DefaultImporter
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import Development_Environment, Engagement, Finding, Product, Product_Type, Test
from dojo.tools.yocto_cve_check.parser import YoctoCveCheckParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


def report(*issues, name="busybox", version="1.36.1"):
    return {"version": "1", "package": [{"name": name, "layer": "meta", "version": version, "issue": list(issues)}]}


def parse_report(data):
    return YoctoCveCheckParser().get_findings(io.StringIO(json.dumps(data)), Test())


def parse_issues(*issues, **package):
    return parse_report(report(*issues, **package))


class TestYoctoCveCheckParser(DojoTestCase):

    def parse(self, filename):
        with (get_unit_tests_scans_path("yocto_cve_check") / filename).open(encoding="utf-8") as testfile:
            return YoctoCveCheckParser().get_findings(testfile, Test())

    def by_id(self, filename):
        return {f.vuln_id_from_tool: f for f in self.parse(filename)}

    def test_parse_no_findings(self):
        # A package with no issues and a package with only Patched issues produce nothing
        self.assertEqual(0, len(self.parse("no_vuln.json")))

    def test_parse_one_finding(self):
        findings = self.parse("one_vuln.json")
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("CVE-2023-42366 in busybox:1.35.0", finding.title)
        # Older manifests have no vectorString or scorev4: severity comes from the v3 score
        self.assertEqual("Medium", finding.severity)
        self.assertEqual(5.5, finding.cvssv3_score)
        self.assertIsNone(finding.cvssv3)
        self.assertIsNone(finding.cvssv4_score)
        self.assertEqual("busybox", finding.component_name)
        self.assertEqual("1.35.0", finding.component_version)
        self.assertEqual("CVE-2023-42366", finding.vuln_id_from_tool)
        self.assertEqual(["CVE-2023-42366"], finding.unsaved_vulnerability_ids)
        self.assertEqual("https://nvd.nist.gov/vuln/detail/CVE-2023-42366", finding.references)
        self.assertTrue(finding.active)
        self.assertFalse(finding.is_mitigated)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

    def test_parse_many_findings(self):
        findings = self.parse("many_vulns.json")
        self.assertEqual(
            ["CVE-2023-51767", "CVE-2024-6387", "CVE-2022-48174", "CVE-2023-42366", "CVE-2005-2096",
             "CVE-2022-25235", "CVE-2025-90001", "CVE-2026-90002"],
            [f.vuln_id_from_tool for f in findings],
        )

    def test_all_findings_have_valid_fields(self):
        for filename in ("one_vuln.json", "many_vulns.json", "sbom_cve_check.json", "whinlatter.json"):
            for finding in self.parse(filename):
                with self.subTest(file=filename, cve=finding.vuln_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
                    self.assertTrue(finding.title.startswith(finding.vuln_id_from_tool))
                    self.assertEqual([finding.vuln_id_from_tool], finding.unsaved_vulnerability_ids)
                    self.assertTrue(finding.component_name)
                    self.assertTrue(finding.component_version)
                    self.assertFalse(finding.false_p)
                    self.assertFalse(finding.out_of_scope)
                    self.assertNotEqual(finding.active, finding.is_mitigated)

    def test_patched_issues_are_skipped(self):
        self.assertNotIn("CVE-2023-38408", self.by_id("many_vulns.json"))
        self.assertNotIn("CVE-2025-90007", self.by_id("whinlatter.json"))

    def test_status_match_ignores_case_and_whitespace(self):
        findings = parse_issues({"id": "CVE-2024-0001", "status": " patched "}, {"id": "CVE-2024-0002", "status": "IGNORED"})
        self.assertEqual(["CVE-2024-0002"], [f.vuln_id_from_tool for f in findings])
        self.assertTrue(findings[0].is_mitigated)

    def test_severity_from_cvss_v3_vector(self):
        finding = self.by_id("many_vulns.json")["CVE-2024-6387"]
        self.assertEqual("High", finding.severity)
        self.assertEqual("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", finding.cvssv3)
        self.assertEqual(8.1, finding.cvssv3_score)

    def test_severity_from_cvss_v2_only(self):
        finding = self.by_id("many_vulns.json")["CVE-2005-2096"]
        self.assertEqual("High", finding.severity)
        self.assertIsNone(finding.cvssv3)
        self.assertIsNone(finding.cvssv3_score)

    def test_v2_vector_does_not_override_newer_v3_score(self):
        # The NVD database used by kirkstone/scarthgap keeps the v2 vector even when a v3 score exists
        finding = self.by_id("many_vulns.json")["CVE-2022-25235"]
        self.assertEqual("Critical", finding.severity)
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertIsNone(finding.cvssv3)

    def test_v3_vector_does_not_override_newer_v4_score(self):
        finding = parse_issues({
            "id": "CVE-2024-0001", "status": "Unpatched", "scorev3": "5.3", "scorev4": "9.3",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        })[0]
        self.assertEqual("Critical", finding.severity)
        self.assertEqual(9.3, finding.cvssv4_score)

    def test_severity_from_cvss_v4_vector(self):
        finding = self.by_id("many_vulns.json")["CVE-2025-90001"]
        self.assertEqual("Critical", finding.severity)
        self.assertEqual("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", finding.cvssv4)
        self.assertEqual(9.3, finding.cvssv4_score)
        self.assertIsNone(finding.cvssv3_score)
        self.assertIn("meta-custom", finding.description)

    def test_unscored_cve_is_info(self):
        finding = self.by_id("many_vulns.json")["CVE-2026-90002"]
        self.assertEqual("Info", finding.severity)
        self.assertEqual("6.6.21+git", finding.component_version)
        self.assertTrue(finding.active)
        self.assertNotIn("UNKNOWN", finding.description)

    def test_out_of_range_scores_are_ignored(self):
        for value in ("11.5", "inf", "nan", "-1", "", None, "n/a"):
            with self.subTest(value=value):
                finding = parse_issues({"id": "CVE-2024-0001", "status": "Unpatched", "scorev3": value})[0]
                self.assertIsNone(finding.cvssv3_score)
                self.assertEqual("Info", finding.severity)

    def test_ignored_issue_is_closed_with_reason(self):
        finding = self.by_id("many_vulns.json")["CVE-2022-48174"]
        self.assertEqual("Critical", finding.severity)
        self.assertFalse(finding.active)
        self.assertTrue(finding.is_mitigated)
        self.assertFalse(finding.false_p)
        self.assertIn("not-applicable-config", finding.mitigation)
        self.assertIn("ash is not enabled", finding.mitigation)
        self.assertIn("| **Status** | Ignored |", finding.description)

    def test_upstream_wontfix_stays_active(self):
        finding = self.by_id("many_vulns.json")["CVE-2023-51767"]
        self.assertTrue(finding.active)
        self.assertFalse(finding.is_mitigated)
        self.assertEqual("High", finding.severity)
        self.assertIn("upstream-wontfix", finding.description)

    def test_every_other_ignored_detail_closes(self):
        details = ["not-applicable-config", "not-applicable-platform", "cpe-incorrect", "disputed", "ignored",
                   "vuln-rejected", "vuln-disputed", "", None, ["unexpected", "shape"]]
        for detail in details:
            with self.subTest(detail=detail):
                finding = parse_issues({"id": "CVE-2024-0001", "status": "Ignored", "detail": detail})[0]
                self.assertFalse(finding.active)
                self.assertTrue(finding.is_mitigated)
                self.assertFalse(finding.false_p)
                self.assertFalse(finding.out_of_scope)

    def test_unpatched_has_no_disposition(self):
        for finding in self.parse("many_vulns.json"):
            if finding.active:
                with self.subTest(cve=finding.vuln_id_from_tool):
                    self.assertFalse(finding.is_mitigated)
                    self.assertIsNone(finding.mitigation)

    def test_description_contains_summary_and_table(self):
        finding = self.by_id("many_vulns.json")["CVE-2024-6387"]
        self.assertIn("signal handler race condition", finding.description)
        self.assertIn("| **Package** | openssh |", finding.description)
        self.assertIn("| **Status** | Unpatched |", finding.description)

    def test_description_table_survives_pipes_and_newlines(self):
        finding = parse_issues({
            "id": "CVE-2024-0001", "status": "Ignored", "detail": "ignored",
            "description": "line one | with a pipe\nline two",
        })[0]
        self.assertIn("| **Status description** | line one \\| with a pipe line two |", finding.description)

    def test_sbom_cve_check_export(self):
        findings = self.by_id("sbom_cve_check.json")
        self.assertEqual(["CVE-2023-42366", "CVE-2026-90003", "CVE-2021-42386"], list(findings))
        self.assertEqual("Medium", findings["CVE-2023-42366"].severity)
        self.assertIn("cpe:2.3:a:busybox:busybox:1.37.0", findings["CVE-2023-42366"].description)
        self.assertIn("NVD last modified", findings["CVE-2023-42366"].description)
        self.assertNotIn("**Layer**", findings["CVE-2023-42366"].description)

    def test_sbom_cve_check_null_status_is_active(self):
        finding = self.by_id("sbom_cve_check.json")["CVE-2026-90003"]
        self.assertEqual("Info", finding.severity)
        self.assertTrue(finding.active)
        self.assertIsNone(finding.cvssv3)
        self.assertIn("No summary available.", finding.description)

    def test_sbom_cve_check_ignored(self):
        finding = self.by_id("sbom_cve_check.json")["CVE-2021-42386"]
        self.assertEqual("High", finding.severity)
        self.assertFalse(finding.active)
        self.assertTrue(finding.is_mitigated)
        self.assertIn("cpe-incorrect", finding.mitigation)

    def test_whinlatter_manifest(self):
        findings = self.by_id("whinlatter.json")
        self.assertEqual(["CVE-2025-90004", "CVE-2025-90005", "CVE-2025-90006"], list(findings))
        self.assertEqual("High", findings["CVE-2025-90004"].severity)
        self.assertIn("version-in-range", findings["CVE-2025-90004"].description)
        # Unknown status, and an issue with no NVD data at all
        self.assertTrue(findings["CVE-2025-90005"].active)
        self.assertEqual("Info", findings["CVE-2025-90005"].severity)
        self.assertTrue(findings["CVE-2025-90006"].is_mitigated)

    def test_bytes_input(self):
        content = (get_unit_tests_scans_path("yocto_cve_check") / "one_vuln.json").read_bytes()
        self.assertEqual(1, len(YoctoCveCheckParser().get_findings(io.BytesIO(content), Test())))

    def test_utf8_bom_input(self):
        content = (get_unit_tests_scans_path("yocto_cve_check") / "one_vuln.json").read_bytes()
        self.assertEqual(1, len(YoctoCveCheckParser().get_findings(io.BytesIO(b"\xef\xbb\xbf" + content), Test())))
        text = "﻿" + content.decode("utf-8")
        self.assertEqual(1, len(YoctoCveCheckParser().get_findings(io.StringIO(text), Test())))

    def test_long_values_fit_model_limits(self):
        finding = parse_issues({"id": "CVE-2024-0001", "status": "Unpatched"}, name="a" * 600, version="1" * 150)[0]
        self.assertEqual(500, len(finding.title))
        self.assertTrue(finding.title.endswith("..."))
        self.assertEqual(500, len(finding.component_name))
        self.assertEqual(100, len(finding.component_version))

    def test_non_string_values_are_coerced(self):
        data = {"version": "1", "package": [{
            "name": None, "version": 2, "products": ["busybox", None], "cpes": "not-a-list",
            "issue": [{"id": "CVE-2024-0001", "status": None, "vectorString": ["x"], "detail": 7}],
        }]}
        finding = parse_report(data)[0]
        self.assertEqual("", finding.component_name)
        self.assertEqual("2", finding.component_version)
        self.assertTrue(finding.active)

    def test_invalid_files_raise(self):
        bad_inputs = [
            '{"vulnerabilities": []}',
            "[]",
            "",
            '{"version": "1", "package": null}',
            '{"version": "1", "package": ["busybox"]}',
            '{"version": "1", "package": [{"name": "busybox", "issue": {"id": "CVE-2024-0001"}}]}',
            '{"version": "1", "package": [{"name": "busybox", "issue": ["CVE-2024-0001"]}]}',
            '{"version": "1", "package": [{"name": "busybox", "issue": [{"status": "Unpatched"}]}]}',
        ]
        for content in bad_inputs:
            with self.subTest(content=content), self.assertRaises(ValueError):
                YoctoCveCheckParser().get_findings(io.StringIO(content), Test())


class TestYoctoCveCheckReimport(DojoTestCase):

    """The Yocto status of a CVE changes between builds; reimport must follow it in both directions."""

    def setUp(self):
        self.user = User.objects.create(username="yocto-reimport", is_superuser=True)
        product = Product.objects.create(
            name="yocto-image", description="Yocto image", prod_type=Product_Type.objects.create(name="yocto"),
        )
        self.engagement = Engagement.objects.create(
            name="builds", product=product, target_start=timezone.now(), target_end=timezone.now(),
        )

    def options(self):
        return {
            "user": self.user, "lead": self.user, "scan_date": None, "active": None, "verified": None,
            "environment": Development_Environment.objects.get_or_create(name="Development")[0],
            "scan_type": "Yocto CVE Check", "close_old_findings": True, "deduplication_execution_mode": "sync",
        }

    def manifest(self, status, detail=None):
        issue = {"id": "CVE-2023-42366", "status": status, "scorev3": "5.5"}
        if detail:
            issue["detail"] = detail
        return SimpleUploadedFile("image.json", json.dumps(report(issue)).encode(), content_type="application/json")

    def reimport(self, test, status, detail=None):
        DefaultReImporter(test=test, **self.options()).process_scan(self.manifest(status, detail))
        return Finding.objects.get(test=test)

    def test_status_changes_round_trip(self):
        test, *_ = DefaultImporter(engagement=self.engagement, **self.options()).process_scan(self.manifest("Unpatched"))
        finding = Finding.objects.get(test=test)
        self.assertTrue(finding.active)

        finding = self.reimport(test, "Ignored", "not-applicable-config")
        self.assertFalse(finding.active)
        self.assertTrue(finding.is_mitigated)

        finding = self.reimport(test, "Unpatched")
        self.assertTrue(finding.active)
        self.assertFalse(finding.is_mitigated)

        finding = self.reimport(test, "Patched")
        self.assertFalse(finding.active)
        self.assertTrue(finding.is_mitigated)

        self.assertEqual(1, Finding.objects.filter(test=test).count())

    def test_ignored_on_first_import_reopens(self):
        test, *_ = DefaultImporter(engagement=self.engagement, **self.options()).process_scan(
            self.manifest("Ignored", "cpe-incorrect"),
        )
        self.assertFalse(Finding.objects.get(test=test).active)
        finding = self.reimport(test, "Unpatched")
        self.assertTrue(finding.active)
        self.assertFalse(finding.is_mitigated)
