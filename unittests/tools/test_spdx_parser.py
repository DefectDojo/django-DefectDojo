from dojo.models import Finding, Test
from dojo.tools.spdx.parser import SpdxParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path, skip_unless_v3


class TestSpdxParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("spdx") / filename).open(encoding="utf-8") as file:
            return list(SpdxParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = SpdxParser()
        self.assertEqual(["SPDX Scan"], parser.get_scan_types())
        self.assertEqual("SPDX Scan", parser.get_label_for_scan_types("SPDX Scan"))
        self.assertIn("SPDX", parser.get_description_for_scan_types("SPDX Scan"))

    def test_no_vuln(self):
        """A pure inventory SBOM yields components but no findings - an installed package is not a weakness."""
        findings = self.parse("spdx_no_vuln.json")
        self.assertEqual(0, len(findings))

    @skip_unless_v3
    def test_no_vuln_still_records_component_inventory(self):
        """
        SPDX must behave like CycloneDX: packages become dependency locations on the test, never findings.

        This is the assertion that stops the parser flooding a product with one un-actionable row per
        installed package.
        """
        test = Test()
        with (get_unit_tests_scans_path("spdx") / "spdx_no_vuln.json").open(encoding="utf-8") as file:
            findings = list(SpdxParser().get_findings(file, test))

        self.assertEqual(0, len(findings))
        self.assertEqual(3, len(test.unsaved_metadata))

        purls = [location.data["purl"] for location in test.unsaved_metadata]
        self.assertIn(
            "pkg:apk/alpine/alpine-baselayout@3.1.2-r0?arch=x86_64&distro=alpine-3.10.9",
            purls,
        )

        first = test.unsaved_metadata[0]
        self.assertEqual("dependency", first.type)
        self.assertEqual("GPL-2.0-only", first.data["license_expression"])

    def test_one_vuln(self):
        findings = self.parse("spdx_one_vuln.json")
        self.assertEqual(1, len(findings))

    def test_one_vuln_field_mapping(self):
        """Full field mapping of the single finding."""
        findings = self.parse("spdx_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("alpine-baselayout:3.1.2-r0 | CVE-2024-10001", finding.title)
        self.assertEqual("alpine-baselayout", finding.component_name)
        self.assertEqual("3.1.2-r0", finding.component_version)
        self.assertEqual("CVE-2024-10001", finding.vuln_id_from_tool)
        self.assertEqual(["CVE-2024-10001"], finding.unsaved_vulnerability_ids)

        # SPDX carries no severity for an advisory reference. Medium is deliberate: a real named CVE
        # must not be filtered out of sight by a minimum-severity setting.
        self.assertEqual("Medium", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)

        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

        self.assertIn("https://example.com/advisories/CVE-2024-10001", finding.references)
        self.assertIn("**advisory:**", finding.references)

        self.assertIn("CVE-2024-10001", finding.description)
        self.assertIn("pkg:apk/alpine/alpine-baselayout@3.1.2-r0", finding.description)
        self.assertIn("GPL-2.0-only", finding.description)
        # The CPE is recorded for identification only.
        self.assertIn("**CPE:**", finding.description)

        self.assertIn("upgrade alpine-baselayout", finding.mitigation)
        self.assertEqual(
            "SPDXRef-Package-apk-alpine-baselayout-d4c11d42e7429ff9|CVE-2024-10001",
            finding.unique_id_from_tool,
        )
        # The document's creationInfo.created drives the finding date.
        self.assertEqual("2026-07-29", finding.date.strftime("%Y-%m-%d"))

    def test_many_vuln(self):
        """
        Three findings from four packages:

        * package 0 names CVE-2024-10001 via BOTH an advisory and a fix ref -> one finding, two refs
        * package 1 names CVE-2024-10002 and a GHSA -> two findings
        * package 2 has an advisory ref with no identifier in it -> no finding
        * package 3 is pure inventory -> no finding
        """
        findings = self.parse("spdx_many_vuln.json")
        self.assertEqual(3, len(findings))

        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)

        ids = sorted(finding.vuln_id_from_tool for finding in findings)
        self.assertEqual(["CVE-2024-10001", "CVE-2024-10002", "GHSA-JFH8-C2JP-5V3Q"], ids)

    def test_many_vuln_collapses_duplicate_identifier(self):
        """A CVE named by both an advisory and a fix reference is one finding carrying both links."""
        findings = self.parse("spdx_many_vuln.json")
        finding = next(f for f in findings if f.vuln_id_from_tool == "CVE-2024-10001")

        self.assertIn("**advisory:** https://example.com/advisories/CVE-2024-10001", finding.references)
        self.assertIn("**fix:** https://example.com/fixes/CVE-2024-10001 (Fixed upstream)", finding.references)

    def test_many_vuln_advisory_without_identifier_is_not_a_finding(self):
        """An advisory reference naming no CVE/GHSA carries no weakness to report."""
        findings = self.parse("spdx_many_vuln.json")
        self.assertNotIn("apk-tools", [finding.component_name for finding in findings])

    def test_cpe_references_never_become_findings(self):
        """
        The regression guard for this parser's central judgement call.

        SPDX puts CPEs under referenceCategory SECURITY, but a CPE identifies what a package IS - it is
        not a vulnerability. Treating the category alone as a weakness signal would turn every
        inventoried package into a bogus finding. spdx_no_vuln.json contains only purl and cpe23Type
        references, so it must produce nothing.
        """
        test = Test()
        with (get_unit_tests_scans_path("spdx") / "spdx_no_vuln.json").open(encoding="utf-8") as file:
            findings = list(SpdxParser().get_findings(file, test))

        self.assertEqual(0, len(findings))
        # But the CPEs really are present in the fixture, so the test is meaningful.
        with (get_unit_tests_scans_path("spdx") / "spdx_no_vuln.json").open(encoding="utf-8") as file:
            self.assertIn("cpe23Type", file.read())

    @skip_unless_v3
    def test_checksums_become_location_hashes(self):
        test = Test()
        with (get_unit_tests_scans_path("spdx") / "spdx_many_vuln.json").open(encoding="utf-8") as file:
            list(SpdxParser().get_findings(file, test))

        hashed = [
            location for location in test.unsaved_metadata if location.data["artifact_hashes"]
        ]
        self.assertEqual(1, len(hashed))
        self.assertEqual(
            ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
            hashed[0].data["artifact_hashes"]["sha256"],
        )

    def test_tag_value_matches_json(self):
        """
        The tag-value serialisation must produce identical findings to JSON.

        Both go through the same mapping code, and this fixture is the JSON one_vuln document
        re-expressed as tag-value.
        """
        findings = self.parse("spdx_one_vuln.spdx")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("alpine-baselayout:3.1.2-r0 | CVE-2024-10001", finding.title)
        self.assertEqual("alpine-baselayout", finding.component_name)
        self.assertEqual("3.1.2-r0", finding.component_version)
        self.assertEqual(["CVE-2024-10001"], finding.unsaved_vulnerability_ids)
        self.assertIn("https://example.com/advisories/CVE-2024-10001", finding.references)

    def test_spdx_3_is_rejected_with_a_clear_message(self):
        """
        SPDX 3.0 uses JSON-LD, a different serialisation entirely.

        Rejecting it loudly is deliberate: silently parsing zero packages out of a valid SBOM would
        look like a clean import of an empty document.
        """
        with (
            (get_unit_tests_scans_path("spdx") / "spdx_3_unsupported.json").open(encoding="utf-8") as file,
            self.assertRaises(ValueError) as context,
        ):
            list(SpdxParser().get_findings(file, Test()))

        self.assertIn("SPDX-3.0", str(context.exception))
        self.assertIn("does not support", str(context.exception))
