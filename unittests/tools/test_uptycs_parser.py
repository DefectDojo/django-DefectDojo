import io
import json

from dojo.models import Finding, Test
from dojo.tools.uptycs.parser import UptycsParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestUptycsParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("uptycs") / filename
        with path.open(encoding="utf-8") as file:
            return list(UptycsParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(UptycsParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def row(self, **overrides):
        row = {"cve_list": ["CVE-2000-0001"], "package_name": "example-lib",
               "package_version": "1.0.0", "cvss_score": 7.5, "upt_asset_id": "asset-1"}
        row.update(overrides)
        return {"items": [row]}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Uptycs connector's ScanTypeName verbatim.

        Note it does NOT follow the "<Vendor> - Connectors Import" pattern the other connector scan
        types use, so it cannot be derived - it has to be copied.
        """
        parser = UptycsParser()
        self.assertEqual(["Uptycs Scan"], parser.get_scan_types())
        self.assertEqual("Uptycs Scan", parser.get_label_for_scan_types("Uptycs Scan"))
        self.assertNotIn("Uptycs - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("uptycs_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("uptycs_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's finding_converter."""
        findings = self.parse("uptycs_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("CVE-2000-0001 in example-tls", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("uptycs-asset-0001-example-tls-CVE-2000-0001", finding.unique_id_from_tool)
        self.assertEqual("CVE-2000-0001", finding.vuln_id_from_tool)
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual("example-tls", finding.component_name)
        self.assertEqual("1.0.2k-1", finding.component_version)
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertTrue(finding.active)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(["Ubuntu 22.04", "production-linux"], finding.unsaved_tags)
        self.assertEqual(
            "**Package:** example-tls 1.0.2k-1\n"
            "**Host:** generic-host-01\n"
            "**OS:** Ubuntu 22.04\n"
            "**Asset group:** production-linux",
            finding.description,
        )

    def test_many_vuln(self):
        """Four rows fan out to seven findings: 3 + 2 + 1 (no CVE) + 1."""
        self.assertEqual(7, len(self.parse("uptycs_many_vuln.json")))

    def test_one_row_becomes_one_finding_per_cve(self):
        """
        Uptycs reports one row per vulnerable package listing every CVE against it.

        Each CVE is separately fixable and separately triaged, so each becomes its own finding rather
        than one finding titled after all of them.
        """
        findings = self.by_uid("uptycs_many_vuln.json")
        for cve in ("CVE-2000-0001", "CVE-2000-0002", "CVE-2000-0003"):
            with self.subTest(cve=cve):
                self.assertIn(f"uptycs-asset-0001-example-tls-{cve}", findings)
                self.assertEqual(f"{cve} in example-tls",
                                 findings[f"uptycs-asset-0001-example-tls-{cve}"].title)

    def test_a_comma_separated_cve_list_is_split(self):
        """
        Uptycs sends the list either as an array or as a comma-separated STRING.

        Reading the string whole would make one finding titled after every CVE at once.
        """
        findings = self.by_uid("uptycs_many_vuln.json")
        self.assertIn("uptycs-asset-0001-example-compress-CVE-2000-0004", findings)
        self.assertIn("uptycs-asset-0001-example-compress-CVE-2000-0005", findings)

    def test_a_comma_separated_list_is_trimmed(self):
        findings = self.parse_string(self.row(cve_list=" CVE-2000-0001 , CVE-2000-0002 ,, "))
        self.assertEqual(["CVE-2000-0001", "CVE-2000-0002"],
                         [finding.vuln_id_from_tool for finding in findings])

    def test_a_row_with_no_cve_is_still_one_finding(self):
        """A vulnerable package is worth recording even when Uptycs attached no identifier."""
        finding = self.by_uid("uptycs_many_vuln.json")["uptycs-asset-0002-example-agent"]
        self.assertEqual("Vulnerable package example-agent", finding.title)
        self.assertIsNone(finding.vuln_id_from_tool)
        self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_a_missing_cve_list_is_not_an_error(self):
        for value in (None, "", [], "not a list but a string with no comma"):
            with self.subTest(value=value):
                findings = self.parse_string(self.row(cve_list=value))
                self.assertEqual(1, len(findings))

    def test_a_row_with_no_package_name_says_package(self):
        finding = self.by_uid("uptycs_many_vuln.json")["uptycs-asset-0003--CVE-2000-0006"]
        self.assertEqual("CVE-2000-0006 in package", finding.title)
        self.assertIsNone(finding.component_name)

    def test_every_cve_from_one_row_shares_the_rows_severity(self):
        """
        The row carries one CVSS score for the package rather than one per CVE.

        So the fan-out cannot grade them apart - which is worth knowing when reading the result.
        """
        findings = self.by_uid("uptycs_many_vuln.json")
        for cve in ("CVE-2000-0001", "CVE-2000-0002", "CVE-2000-0003"):
            with self.subTest(cve=cve):
                finding = findings[f"uptycs-asset-0001-example-tls-{cve}"]
                self.assertEqual("Critical", finding.severity)
                self.assertEqual(9.8, finding.cvssv3_score)

    def test_cvss_score_bands(self):
        """Uptycs sends no severity word, so the score is the only signal."""
        for score, expected in ((9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low"),
                                (0, "Info")):
            with self.subTest(score=score):
                findings = self.parse_string(self.row(cvss_score=score))
                self.assertEqual(expected, findings[0].severity)

    def test_a_quoted_score_is_accepted(self):
        finding = self.by_uid("uptycs_many_vuln.json")[
            "uptycs-asset-0001-example-compress-CVE-2000-0004"]
        self.assertEqual(7.5, finding.cvssv3_score)
        self.assertEqual("High", finding.severity)

    def test_the_other_cves_are_listed_only_when_the_row_names_more_than_one(self):
        """
        With a single CVE the title already says it, so repeating it in the body adds nothing.

        With several, the list tells a reader that the other findings exist.
        """
        findings = self.by_uid("uptycs_many_vuln.json")
        several = findings["uptycs-asset-0001-example-tls-CVE-2000-0001"]
        self.assertIn("**CVEs:** CVE-2000-0001, CVE-2000-0002, CVE-2000-0003", several.description)

        single = findings["uptycs-asset-0003--CVE-2000-0006"]
        self.assertNotIn("**CVEs:**", single.description)

        none = findings["uptycs-asset-0002-example-agent"]
        self.assertNotIn("**CVEs:**", none.description)

    def test_the_identity_spans_the_asset_and_the_package(self):
        """
        The same CVE on two hosts is two findings - two machines to patch.

        The component is the package, so the hash alone would merge them; the asset id in the identity
        is what keeps them apart.
        """
        self.assertEqual(["title", "severity", "component_name"], UptycsParser().get_dedupe_fields())
        row = {"cve_list": ["CVE-2000-0001"], "package_name": "example-lib", "cvss_score": 7.5}
        findings = self.parse_string({"items": [
            {**row, "upt_asset_id": "asset-a"},
            {**row, "upt_asset_id": "asset-b"},
        ]})
        self.assertEqual(["uptycs-asset-a-example-lib-CVE-2000-0001",
                          "uptycs-asset-b-example-lib-CVE-2000-0001"],
                         [finding.unique_id_from_tool for finding in findings])

    def test_absent_description_fields_are_left_out(self):
        finding = self.by_uid("uptycs_many_vuln.json")["uptycs-asset-0003--CVE-2000-0006"]
        self.assertNotIn("**Host:**", finding.description)
        self.assertNotIn("**OS:**", finding.description)
        self.assertNotIn("**Asset group:**", finding.description)

    def test_a_row_with_no_asset_group_tags_only_the_os(self):
        finding = self.by_uid("uptycs_many_vuln.json")["uptycs-asset-0002-example-agent"]
        self.assertEqual(["Windows Server 2019"], finding.unsaved_tags)

    def test_export_shapes(self):
        row = {"cve_list": ["CVE-2000-0001"], "package_name": "example-lib", "cvss_score": 7.5}
        for payload in ([row], {"items": [row]}, {"rows": [row]}, {"data": [row]},
                        {"results": [row]}):
            with self.subTest(shape=str(payload)[:22]):
                self.assertEqual(1, len(self.parse_string(payload)))

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("Uptycs", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("items", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"items": [
            "not an object",
            None,
            {"cve_list": ["CVE-2000-0009", "", "  "], "package_name": "example-lib",
             "cvss_score": 5.0, "upt_asset_id": "asset-9"},
        ]})
        self.assertEqual(1, len(findings))
        self.assertEqual("uptycs-asset-9-example-lib-CVE-2000-0009",
                         findings[0].unique_id_from_tool)

    def test_severity_is_always_a_known_value(self):
        for filename in ("uptycs_many_vuln.json", "uptycs_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
