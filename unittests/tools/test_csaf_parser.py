from dojo.models import Finding, Test
from dojo.tools.csaf.parser import CsafParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestCsafParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("csaf") / filename).open(encoding="utf-8") as file:
            return list(CsafParser().get_findings(file, Test()))

    def by_component(self, findings, component_name, component_version=None):
        for finding in findings:
            if finding.component_name == component_name and (
                component_version is None or finding.component_version == component_version
            ):
                return finding
        msg = f"no finding for {component_name} {component_version}"
        raise AssertionError(msg)

    def test_scan_type_metadata(self):
        parser = CsafParser()
        self.assertEqual(["CSAF Scan"], parser.get_scan_types())
        self.assertEqual("CSAF Scan", parser.get_label_for_scan_types("CSAF Scan"))
        self.assertIn("CSAF", parser.get_description_for_scan_types("CSAF Scan"))

    def test_no_vuln(self):
        """
        A valid advisory with no vulnerabilities yields nothing.

        CSAF 2.0 sets minItems=1 on `vulnerabilities`, so a document with none omits the key entirely
        rather than carrying an empty array - the fixture reflects that.
        """
        self.assertEqual(0, len(self.parse("csaf_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("csaf_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        findings = self.parse("csaf_one_vuln.json")
        finding = findings[0]

        self.assertEqual("Generic App:1.0.0 | CVE-2026-10001", finding.title)
        self.assertEqual("Generic App", finding.component_name)
        self.assertEqual("1.0.0", finding.component_version)
        self.assertEqual("CVE-2026-10001", finding.vuln_id_from_tool)
        self.assertEqual(["CVE-2026-10001"], finding.unsaved_vulnerability_ids)

        # cvss_v3.baseSeverity CRITICAL -> Critical, with score and vector carried across.
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", finding.cvssv3)

        self.assertEqual(94, finding.cwe)
        self.assertTrue(finding.active, "known_affected must be active")
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

        self.assertEqual("CSAFPID-0001|CVE-2026-10001", finding.unique_id_from_tool)

        self.assertIn("known_affected", finding.description)
        self.assertIn("unauthenticated attacker", finding.description)
        self.assertIn("Example Corp (vendor)", finding.description)
        self.assertIn("CVSS base score", finding.description)

        self.assertIn("vendor_fix", finding.mitigation)
        self.assertIn("Upgrade to Generic App 1.0.1.", finding.mitigation)
        self.assertIn("Restart required: service", finding.mitigation)

        self.assertIn("https://example.com/advisories/EXAMPLE-2026-0001", finding.references)
        self.assertEqual("2026-07-29", finding.date.strftime("%Y-%m-%d"))

    def test_many_vuln(self):
        """
        Five findings: four product-status buckets on the first CVE, plus the second vulnerability.

        One advisory routinely covers several products in different states, which is why the parser
        emits one finding per (vulnerability, product) rather than per vulnerability.
        """
        findings = self.parse("csaf_many_vuln.json")
        self.assertEqual(5, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)

    def test_known_not_affected_is_never_active(self):
        """
        ★ The critical assertion for this parser.

        The advisory explicitly lists Generic App 2.0.0 as known_not_affected. Importing that as active
        would turn the vendor's "you are fine" into work.
        """
        findings = self.parse("csaf_many_vuln.json")
        not_affected = self.by_component(findings, "Generic App", "2.0.0")

        self.assertFalse(not_affected.active, "known_not_affected must never be active")
        self.assertTrue(not_affected.false_p)
        self.assertIn("imported inactive", not_affected.description)
        self.assertIn("known_not_affected", not_affected.description)
        self.assertIn("No action required", not_affected.mitigation)

    def test_product_status_matrix(self):
        findings = self.parse("csaf_many_vuln.json")

        affected = self.by_component(findings, "Generic App", "1.0.0")
        self.assertTrue(affected.active)
        self.assertEqual("High", affected.severity)
        self.assertEqual(7.5, affected.cvssv3_score)
        # Both remediations for this product are carried.
        self.assertIn("vendor_fix", affected.mitigation)
        self.assertIn("workaround", affected.mitigation)

        fixed = self.by_component(findings, "Generic App", "1.0.1")
        self.assertFalse(fixed.active)
        self.assertTrue(fixed.is_mitigated)

        investigating = self.by_component(findings, "Generic Library", "3.4.5")
        self.assertTrue(investigating.active)
        self.assertFalse(investigating.verified)

    def test_branch_shaped_product_tree_resolves_versions(self):
        """
        The version of a branch-shaped product lives on a `product_version` branch, not in the leaf
        name, so the tree has to be walked rather than flattened.
        """
        findings = self.parse("csaf_many_vuln.json")
        versions = sorted(
            f.component_version for f in findings if f.component_name == "Generic App"
        )
        self.assertEqual(["1.0.0", "1.0.1", "2.0.0"], versions)

    def test_relationship_defines_its_own_product(self):
        """
        A CSAF relationship synthesises a NEW product id ("library as a component of app") with its own
        full_product_name, which must resolve rather than falling back to the raw id.
        """
        findings = self.parse("csaf_many_vuln.json")
        finding = next(f for f in findings if f.unique_id_from_tool.startswith("CSAFPID-0005|"))

        self.assertIn("Generic Library 3.4.5 as a component of Generic App", finding.component_name)
        self.assertTrue(finding.active)

    def test_embargoed_vulnerability_uses_tracking_id(self):
        """A vulnerability with no CVE yet falls back to its ids[] entry for identity."""
        findings = self.parse("csaf_many_vuln.json")
        finding = next(f for f in findings if f.vuln_id_from_tool == "EXAMPLE-2026-0002-B")

        self.assertEqual(["EXAMPLE-2026-0002-B"], finding.unsaved_vulnerability_ids)
        # No scores at all in the advisory -> Medium, not Info. A published vendor advisory is not
        # informational, and Info would hide it behind a minimum-severity setting.
        self.assertEqual("Medium", finding.severity)

    def test_csaf_1_x_is_rejected(self):
        with (
            (get_unit_tests_scans_path("csaf") / "csaf_unsupported_version.json").open(encoding="utf-8") as file,
            self.assertRaises(ValueError) as context,
        ):
            list(CsafParser().get_findings(file, Test()))

        self.assertIn("not supported", str(context.exception))
        self.assertIn("CVRF", str(context.exception))
