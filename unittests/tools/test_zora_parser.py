from dojo.models import Test
from dojo.tools.zora.parser import ZoraParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestZoraParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_finding(self):
        with (get_unit_tests_scans_path("zora") / "scan_empty.csv").open(encoding="utf-8") as testfile:
            content = testfile.read()  # Read raw content
            parser = ZoraParser()
            findings = parser.get_findings(content, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_many_vuln_has_many_findings(self):
        with (get_unit_tests_scans_path("zora") / "scan_many.csv").open(encoding="utf-8") as testfile:
            content = testfile.read()  # Read raw content
            parser = ZoraParser()
            findings = parser.get_findings(content, Test())
            self.assertEqual(198, len(findings))  # Adjust based on your test file
            # Check a specific finding for correctness
            finding = findings[0]
            self.assertEqual(True, finding.fix_available)
            self.assertEqual("1.2.5-r1", finding.fix_version)
            finding = findings[1]
            self.assertEqual(False, finding.fix_available)
            self.assertEqual(None, finding.fix_version)
            finding = findings[2]
            self.assertEqual(False, finding.fix_available)
            self.assertEqual(None, finding.fix_version)
            finding = findings[3]
            self.assertEqual(True, finding.fix_available)
            self.assertEqual("3.3.5-r0", finding.fix_version)
            finding = findings[10]
            self.assertEqual("net/url: Insufficient validation of bracketed IPv6 hostnames in net/url", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertTrue(finding.unique_id_from_tool.startswith(f"{finding.description.splitlines()[0].split(': ')[1]}"))
            self.assertEqual('**Source**: Trivy\n**Image**: ghcr.io/undistro/popeye:0.21\n**ID**: CVE-2025-47912\n**Details**: The Parse function permits values other than IPv6 addresses to be included in square brackets within the host component of a URL. RFC 3986 permits IPv6 addresses to be included within the host component, enclosed within square brackets. For example: "http://[::1]/". IPv4 addresses and hostnames must not appear within square brackets. Parse did not enforce this requirement.\n', finding.description)
