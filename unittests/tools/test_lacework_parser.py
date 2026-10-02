import io
import json

from dojo.models import Finding, Test
from dojo.tools.lacework.parser import LaceworkParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestLaceworkParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("lacework") / filename).open(encoding="utf-8") as file:
            return list(LaceworkParser().get_findings(file, Test()))

    def by_uid(self, filename):
        return {f.unique_id_from_tool: f for f in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Lacework connector's ScanType() verbatim.

        Any drift and a customer who uploads an export and also syncs the API gets two
        un-deduplicated copies of every finding.
        """
        parser = LaceworkParser()
        self.assertEqual(["Lacework - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "Lacework - Connectors Import",
            parser.get_label_for_scan_types("Lacework - Connectors Import"),
        )

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("lacework_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("lacework_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring ContainerToFinding in the connector's converter."""
        findings = self.parse("lacework_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        # converter title(): "<CVE> - <package> (<version>)"
        self.assertEqual("CVE-2000-0001 - openssl (3.0.11-1)", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("openssl", finding.component_name)
        self.assertEqual("3.0.11-1", finding.component_version)
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual("Upgrade openssl to 3.0.13-1.", finding.mitigation)
        # converter: imageId|vulnId|package|version
        self.assertEqual(
            "sha256:aaaa1111|CVE-2000-0001|openssl|3.0.11-1", finding.unique_id_from_tool,
        )

        self.assertIn("**Image:** registry.example.com/generic-app", finding.description)
        self.assertIn("**Registry:** registry.example.com", finding.description)
        self.assertIn("**Image Digest:** sha256:bbbb2222", finding.description)
        self.assertIn("**Namespace:** debian:12", finding.description)

    def test_a_container_row_is_static_and_a_host_row_is_dynamic(self):
        """
        The connector has two mappings and flags them oppositely.

        An image scan reads a built artifact (static); a host scan looks at a running machine
        (dynamic). Collapsing the two would misreport half the findings.
        """
        findings = self.by_uid("lacework_many_vuln.json")

        container = findings["sha256:aaaa1111|CVE-2000-0001|openssl|3.0.11-1"]
        self.assertTrue(container.static_finding)
        self.assertFalse(container.dynamic_finding)
        self.assertEqual(
            ["image:registry.example.com/generic-app",
             "registry:registry.example.com",
             "source:container"],
            container.unsaved_tags,
        )

        host = findings["host01.example.com|CVE-2000-0002|curl|7.81.0-1"]
        self.assertFalse(host.static_finding)
        self.assertTrue(host.dynamic_finding)
        self.assertEqual(["host:host01.example.com", "source:host"], host.unsaved_tags)
        # Only host rows carry the CVE link as a reference.
        self.assertEqual("https://example.com/cve-2000-0002", host.references)
        self.assertIn("**Description:** A flaw in URL parsing.", host.description)

    def test_the_unique_id_is_keyed_by_image_for_containers_and_host_for_hosts(self):
        """The connector composes different identities for the two shapes."""
        uids = set(self.by_uid("lacework_many_vuln.json"))
        self.assertIn("sha256:aaaa1111|CVE-2000-0001|openssl|3.0.11-1", uids)
        self.assertIn("host01.example.com|CVE-2000-0002|curl|7.81.0-1", uids)

    def test_a_fixed_row_is_imported_but_not_active(self):
        """Converter applyStatus(): Lacework's own status decides, and "Fixed" is not active."""
        finding = self.by_uid("lacework_many_vuln.json")["sha256:cccc3333|CVE-2000-0003|zlib|1.2.13"]
        self.assertFalse(finding.active)
        self.assertTrue(finding.is_mitigated)
        self.assertEqual("Medium", finding.severity)

    def test_no_mitigation_without_both_a_fix_flag_and_a_fixed_version(self):
        finding = self.by_uid("lacework_many_vuln.json")["sha256:cccc3333|CVE-2000-0003|zlib|1.2.13"]
        self.assertIsNone(finding.mitigation)

    def test_a_host_row_reports_fix_available_as_a_string(self):
        """
        Container rows use an integer fix_available, host rows a string.

        Testing one shape's type against the other would silently drop every host mitigation.
        """
        finding = self.by_uid("lacework_many_vuln.json")["host01.example.com|CVE-2000-0002|curl|7.81.0-1"]
        self.assertEqual("Upgrade curl to 7.81.0-4.", finding.mitigation)

    def test_a_host_row_with_no_hostname_falls_back_to_the_machine_id(self):
        """converter: host = fmt.Sprintf("mid-%d", vuln.Mid) when the hostname is empty."""
        finding = self.by_uid("lacework_many_vuln.json")["mid-77|||"]
        self.assertEqual(["host:mid-77", "source:host"], finding.unsaved_tags)

    def test_a_row_with_no_cve_or_package_still_gets_a_title(self):
        """Converter title(): the identifier falls back to "Vulnerability"."""
        finding = self.by_uid("lacework_many_vuln.json")["mid-77|||"]
        self.assertEqual("Vulnerability", finding.title)
        self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_an_unrecognised_severity_is_info(self):
        finding = self.by_uid("lacework_many_vuln.json")["mid-77|||"]
        self.assertEqual("Info", finding.severity)

    def test_a_bare_row_array_is_accepted(self):
        report = io.StringIO(json.dumps([{
            "imageId": "img", "vulnId": "CVE-1", "severity": "Low",
            "evalCtx": {"image_info": {"repo": "r", "registry": "reg"}},
            "featureKey": {"name": "p", "version": "1"},
        }]))
        self.assertEqual(1, len(list(LaceworkParser().get_findings(report, Test()))))

    def test_a_repeated_row_collapses_on_the_unique_id(self):
        row = {
            "imageId": "img", "vulnId": "CVE-1", "severity": "Low",
            "evalCtx": {"image_info": {"repo": "r", "registry": "reg"}},
            "featureKey": {"name": "p", "version": "1"},
        }
        report = io.StringIO(json.dumps({"data": [row, row]}))
        self.assertEqual(1, len(list(LaceworkParser().get_findings(report, Test()))))

    def test_an_unexpected_shape_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(LaceworkParser().get_findings(io.StringIO('"nope"'), Test()))
        self.assertIn("vulnerability rows", str(raised.exception))
