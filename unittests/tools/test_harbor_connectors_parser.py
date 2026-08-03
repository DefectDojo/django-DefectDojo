import io
import json

from dojo.models import Finding, Test
from dojo.tools.harbor_connectors.parser import HarborConnectorsParser
from dojo.tools.harbor_vulnerability.parser import HarborVulnerabilityParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestHarborConnectorsParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("harbor_connectors") / filename
        with path.open(encoding="utf-8") as file:
            return list(HarborConnectorsParser().get_findings(file, Test()))

    def by_uid(self, filename):
        return {f.unique_id_from_tool: f for f in self.parse(filename)}

    def test_scan_type_matches_the_connector_and_does_not_clash(self):
        """
        Must equal the Harbor connector's ScanType() verbatim.

        DefectDojo already ships a `harbor_vulnerability` parser under "Harbor Vulnerability Scan".
        Two scan types, so neither shadows the other in the import dropdown.
        """
        parser = HarborConnectorsParser()
        self.assertEqual(["Harbor - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "Harbor - Connectors Import",
            parser.get_label_for_scan_types("Harbor - Connectors Import"),
        )
        self.assertEqual(
            ["Harbor Vulnerability Scan"], HarborVulnerabilityParser().get_scan_types(),
        )
        self.assertNotEqual(
            HarborVulnerabilityParser().get_scan_types(), parser.get_scan_types(),
        )

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("harbor_connectors_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("harbor_connectors_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring VulnerabilityToFinding in the connector's converter."""
        findings = self.parse("harbor_connectors_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("CVE-2000-0001 - openssl (3.0.11-1)", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("openssl", finding.component_name)
        self.assertEqual("3.0.11-1", finding.component_version)
        self.assertEqual("generic-project/generic-app", finding.service)
        self.assertEqual(295, finding.cwe)
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual("Upgrade openssl to version 3.0.13-1", finding.mitigation)
        self.assertEqual(
            "https://example.com/advisories/cve-2000-0001\nhttps://example.com/tracker/1",
            finding.references,
        )
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

    def test_the_mime_keyed_envelope_is_unwrapped(self):
        """
        Harbor's scan endpoint keys the report by the scanner's MIME type.

        A saved export is therefore usually an object whose single key is something like
        "application/vnd.security.vulnerability.report; version=1.1". Expecting the bare report would
        reject every real export.
        """
        raw = json.loads((get_unit_tests_scans_path("harbor_connectors")
                          / "harbor_connectors_one_vuln.json").read_text(encoding="utf-8"))
        self.assertEqual(1, len(raw))
        self.assertIn("vnd.security.vulnerability.report", next(iter(raw)))
        self.assertNotIn("vulnerabilities", raw)

        self.assertEqual(1, len(self.parse("harbor_connectors_one_vuln.json")))

    def test_the_bare_report_object_is_also_accepted(self):
        report = io.StringIO(json.dumps({
            "repository": "generic-project/generic-app", "digest": "sha256:aaaa",
            "vulnerabilities": [{"id": "CVE-2000-0001", "package": "p", "version": "1",
                                 "severity": "High"}],
        }))
        findings = list(HarborConnectorsParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("High", findings[0].severity)

    def test_the_unique_id_composes_the_repository_artifact_and_package(self):
        """
        The connector's identity, which is also the whole dedup hash for this scan type.

        Getting it wrong would either merge findings across artifacts or reimport on every scan.
        """
        finding = self.parse("harbor_connectors_one_vuln.json")[0]
        self.assertEqual(
            "generic-project/generic-app@"
            "sha256:aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbb8888"
            ":CVE-2000-0001:openssl:3.0.11-1",
            finding.unique_id_from_tool,
        )

    def test_the_digest_is_preferred_over_the_tag_in_the_identity(self):
        """
        A tag can be moved to a different image, so keying on it would silently merge findings from
        two artifacts.

        The connector falls back to the tag only when there is no digest.
        """
        parser = HarborConnectorsParser()
        with_digest = parser.unique_id(
            {}, {"repository": "r", "tag": "latest", "digest": "sha256:abc"}, "p", "1", "CVE-1",
        )
        self.assertIn("sha256:abc", with_digest)
        self.assertNotIn("latest", with_digest)

        without = parser.unique_id(
            {}, {"repository": "r", "tag": "latest", "digest": ""}, "p", "1", "CVE-1",
        )
        self.assertEqual("r@latest:CVE-1:p:1", without)

    def test_the_image_context_is_appended_to_the_description(self):
        """
        The artifact identity is not in Harbor's report body at all - the connector supplies it from
        the artifact it fetched.

        Without it a finding gives no clue which image it came from.
        """
        finding = self.parse("harbor_connectors_one_vuln.json")[0]
        self.assertIn("A flaw in certificate verification", finding.description)
        self.assertIn("**Image:** generic-project/generic-app:1.4.0", finding.description)
        self.assertIn(
            "**Digest:** sha256:aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbb8888",
            finding.description,
        )

    def test_an_advisory_with_no_description_says_so(self):
        """
        Harbor omits the description on plenty of advisories.

        The connector writes a placeholder rather than leaving the field empty, which would read as a
        parser bug.
        """
        finding = self.by_uid("harbor_connectors_many_vuln.json")[
            "generic-project/generic-app@"
            "sha256:aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbb8888"
            ":CVE-2000-0002:curl:7.81.0-1"
        ]
        self.assertTrue(finding.description.startswith("No description found"))
        self.assertIn("**Image:**", finding.description)

    def test_no_mitigation_without_a_fix_version(self):
        findings = self.parse("harbor_connectors_many_vuln.json")
        curl = next(f for f in findings if f.component_name == "curl")
        self.assertIsNone(curl.mitigation)
        self.assertIsNone(curl.references)

    def test_only_a_cve_id_becomes_a_vulnerability_id(self):
        """
        Harbor also reports GHSA and distro advisory ids, and the connector records only CVEs.

        Putting a GHSA in unsaved_vulnerability_ids would have DefectDojo try to resolve it as a CVE.
        """
        findings = self.parse("harbor_connectors_many_vuln.json")
        ghsa = next(f for f in findings if f.component_name == "zlib")
        self.assertEqual("GHSA-0000-0000-0003 - zlib (1.2.13)", ghsa.title)
        self.assertIsNone(ghsa.unsaved_vulnerability_ids)

        cve = next(f for f in findings if f.component_name == "openssl")
        self.assertEqual(["CVE-2000-0001"], cve.unsaved_vulnerability_ids)

    def test_an_unparseable_cwe_leaves_the_cwe_at_zero(self):
        findings = self.parse("harbor_connectors_many_vuln.json")
        for name in ("zlib", "busybox"):
            finding = next(f for f in findings if f.component_name == name)
            self.assertEqual(0, finding.cwe, name)

    def test_the_first_cwe_is_used(self):
        parser = HarborConnectorsParser()
        self.assertEqual(295, parser.first_cwe(["CWE-295", "CWE-297"]))
        self.assertEqual(0, parser.first_cwe(["not-a-cwe", "CWE-295"]))
        self.assertEqual(0, parser.first_cwe([]))
        self.assertEqual(0, parser.first_cwe(None))

    def test_an_unrecognised_severity_is_info(self):
        findings = self.parse("harbor_connectors_many_vuln.json")
        finding = next(f for f in findings if f.component_name == "busybox")
        self.assertEqual("Info", finding.severity)

    def test_many_vuln(self):
        findings = self.parse("harbor_connectors_many_vuln.json")
        self.assertEqual(4, len(findings))
        self.assertEqual(
            {"openssl", "curl", "zlib", "busybox"}, {f.component_name for f in findings},
        )
        # Every finding carries the repository as its service.
        self.assertEqual({"generic-project/generic-app"}, {f.service for f in findings})

    def test_an_export_with_no_artifact_context_still_imports(self):
        """
        The context is not in Harbor's report body, so a bare report may lack it.

        The finding still imports; its tool id simply has empty repository and artifact segments,
        which is the connector's own behaviour when the fields are blank.
        """
        report = io.StringIO(json.dumps({"vulnerabilities": [
            {"id": "CVE-2000-0001", "package": "p", "version": "1", "severity": "Low"},
        ]}))
        finding = list(HarborConnectorsParser().get_findings(report, Test()))[0]
        self.assertEqual("@:CVE-2000-0001:p:1", finding.unique_id_from_tool)
        self.assertIsNone(finding.service)

    def test_a_bare_vulnerability_array_is_accepted(self):
        report = io.StringIO(json.dumps([
            {"id": "CVE-2000-0001", "package": "p", "version": "1", "severity": "Low"},
        ]))
        self.assertEqual(1, len(list(HarborConnectorsParser().get_findings(report, Test()))))

    def test_a_repeated_vulnerability_collapses(self):
        row = {"id": "CVE-2000-0001", "package": "p", "version": "1", "severity": "Low"}
        report = io.StringIO(json.dumps({"vulnerabilities": [row, row]}))
        self.assertEqual(1, len(list(HarborConnectorsParser().get_findings(report, Test()))))

    def test_an_unexpected_shape_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(HarborConnectorsParser().get_findings(io.StringIO('"nope"'), Test()))
        self.assertIn("vulnerabilities", str(raised.exception))

    def test_an_object_with_no_report_anywhere_is_rejected(self):
        with self.assertRaises(TypeError) as raised:
            list(HarborConnectorsParser().get_findings(
                io.StringIO(json.dumps({"unrelated": {"foo": 1}})), Test(),
            ))
        self.assertIn("vulnerabilities", str(raised.exception))
