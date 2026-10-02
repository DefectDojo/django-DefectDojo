from dojo.models import Finding, Test
from dojo.tools.openvex.parser import OpenVEXParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestOpenVEXParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("openvex") / filename).open(encoding="utf-8") as file:
            return list(OpenVEXParser().get_findings(file, Test()))

    def by_vuln(self, findings, vulnerability_id):
        return next(f for f in findings if f.vuln_id_from_tool == vulnerability_id)

    def test_scan_type_metadata(self):
        parser = OpenVEXParser()
        self.assertEqual(["OpenVEX Scan"], parser.get_scan_types())
        self.assertEqual("OpenVEX Scan", parser.get_label_for_scan_types("OpenVEX Scan"))
        self.assertIn("suppression", parser.get_description_for_scan_types("OpenVEX Scan"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("openvex_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("openvex_one_vuln.json")))

    def test_not_affected_is_never_active(self):
        """
        ★ The single most important assertion in this parser.

        A VEX not_affected statement is the producer saying "you are safe from this". Importing it as
        an active finding would invert the document's meaning and turn reassurance into new work -
        making DefectDojo worse than not reading the document at all.
        """
        findings = self.parse("openvex_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertFalse(finding.active, "a not_affected statement must never be active")
        self.assertTrue(finding.false_p, "vulnerable_code_not_present means the match is a false positive")
        self.assertFalse(getattr(finding, "is_mitigated", False))

    def test_one_vuln_field_mapping(self):
        findings = self.parse("openvex_one_vuln.json")
        finding = findings[0]

        self.assertEqual("pkg:apk/alpine/apk-tools:2.10.6-r0 | CVE-2024-10001", finding.title)
        self.assertEqual("pkg:apk/alpine/apk-tools", finding.component_name)
        self.assertEqual("2.10.6-r0", finding.component_version)
        self.assertEqual("CVE-2024-10001", finding.vuln_id_from_tool)
        self.assertEqual(["CVE-2024-10001"], finding.unsaved_vulnerability_ids)

        # VEX states exploitability, not impact, so a suppressed finding is Info - it exists to
        # suppress, not to be worked, and ranking it would push it in front of real findings.
        self.assertEqual("Info", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)

        self.assertEqual(
            "pkg:apk/alpine/apk-tools@2.10.6-r0?arch=x86_64&distro=alpine-3.10.9|CVE-2024-10001",
            finding.unique_id_from_tool,
        )

        self.assertIn("is **not_affected**", finding.description)
        self.assertIn("imported inactive", finding.description)
        self.assertIn("vulnerable_code_not_present", finding.description)
        self.assertIn("The vulnerable code is not present", finding.description)
        self.assertIn("Example Org", finding.description)
        self.assertIn("No action required", finding.mitigation)
        self.assertIn("openvex.dev/ns/v0.2.0", finding.references)
        self.assertEqual("2026-07-29", finding.date.strftime("%Y-%m-%d"))

    def test_many_vuln(self):
        findings = self.parse("openvex_many_vuln.json")
        self.assertEqual(6, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)

    def test_status_matrix(self):
        """
        The full status matrix, which is the contract this parser has to honour.

        Only `affected` and `under_investigation` are active. Everything else suppresses.
        """
        findings = self.parse("openvex_many_vuln.json")

        # not_affected + vulnerable_code_not_present -> inactive false positive
        not_affected = self.by_vuln(findings, "CVE-2024-10001")
        self.assertFalse(not_affected.active)
        self.assertTrue(not_affected.false_p)

        # affected -> ACTIVE, because the producer asserts real exposure
        affected = self.by_vuln(findings, "CVE-2024-10002")
        self.assertTrue(affected.active, "an affected statement is the one that must stay active")
        self.assertEqual("Medium", affected.severity)
        self.assertFalse(affected.false_p)
        self.assertFalse(getattr(affected, "out_of_scope", False))

        # fixed -> inactive and mitigated
        fixed = self.by_vuln(findings, "CVE-2024-10003")
        self.assertFalse(fixed.active)
        self.assertTrue(fixed.is_mitigated)
        self.assertIn("reports this vulnerability as fixed", fixed.mitigation)

        # under_investigation -> active but unverified; the producer has not decided
        investigating = self.by_vuln(findings, "CVE-2024-10004")
        self.assertTrue(investigating.active)
        self.assertFalse(investigating.verified)
        self.assertEqual("Info", investigating.severity)
        self.assertIn("not yet determined", investigating.description)

    def test_justification_drives_disposition(self):
        """
        The five not_affected justifications say materially different things, so each maps to the
        DefectDojo field that matches it rather than being collapsed into one disposition.
        """
        findings = self.parse("openvex_many_vuln.json")

        # inline_mitigations_already_exist -> a real mitigation exists
        mitigated = self.by_vuln(findings, "CVE-2024-10005")
        self.assertFalse(mitigated.active)
        self.assertTrue(mitigated.is_mitigated)
        self.assertFalse(mitigated.false_p)
        self.assertIn("The affected code path is disabled at build time.", mitigated.description)
        # aliases join the primary identifier
        self.assertEqual(["CVE-2024-10005", "GHSA-jfh8-c2jp-5v3q"], mitigated.unsaved_vulnerability_ids)

        # component_not_present -> the finding does not apply to this product at all
        absent = self.by_vuln(findings, "CVE-2024-10006")
        self.assertFalse(absent.active)
        self.assertTrue(absent.out_of_scope)
        self.assertFalse(absent.false_p)

    def test_v0_0_1_bare_string_shape(self):
        """
        OpenVEX v0.0.1 used bare strings for `vulnerability` and `products`; v0.2.0 uses objects.

        Older producers still emit the v0.0.1 shape, and failing to read it would silently drop
        suppression statements - the worst possible failure mode for a VEX parser.
        """
        findings = self.parse("openvex_many_vuln.json")
        legacy = self.by_vuln(findings, "CVE-2024-10006")

        self.assertEqual("pkg:apk/alpine/openssl", legacy.component_name)
        self.assertEqual("1.1.1k-r0", legacy.component_version)
        self.assertFalse(legacy.active)

    def test_non_object_document_is_rejected(self):
        with (
            (get_unit_tests_scans_path("openvex") / "openvex_not_a_document.json").open(encoding="utf-8") as file,
            self.assertRaises(TypeError),
        ):
            list(OpenVEXParser().get_findings(file, Test()))
