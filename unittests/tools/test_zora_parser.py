
import csv

from dojo.models import Test
from dojo.tools.zora.parser import ZoraParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestZoraParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_finding(self):
        with (get_unit_tests_scans_path("zora") / "scan_empty.csv").open(encoding="utf-8") as testfile:
            reader = csv.DictReader(testfile)
            parser = ZoraParser()
            findings = parser.get_findings(Test(), reader)
            self.assertEqual(0, len(findings))

    def test_parse_file_with_many_vuln_has_many_findings(self):
        with (get_unit_tests_scans_path("zora") / "scan_many.csv").open(encoding="utf-8") as testfile:
            reader = csv.DictReader(testfile)
            parser = ZoraParser()
            findings = parser.get_findings(Test(), reader)
            self.assertEqual(198, len(findings))  # Adjust based on your test file
            # Check a specific finding for correctness
            finding = findings[10]
            self.assertEqual("net/url: Insufficient validation of bracketed IPv6 hostnames in net/url", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertTrue(finding.unique_id_from_tool.startswith(f"{finding.description.splitlines()[0].split(': ')[1]}"))
            self.assertIn("Fix Version", finding.description)
