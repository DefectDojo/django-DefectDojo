from dojo.models import Test
from dojo.tools.betterleaks.parser import BetterleaksParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestBetterleaksParser(DojoTestCase):
    def test_parse_file_legacy_with_no_findings(self):
        with (get_unit_tests_scans_path("betterleaks") / "betterleaks_no_vuln.json").open(encoding="utf-8") as testfile:
            parser = BetterleaksParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_legacy_with_one_finding(self):
        with (get_unit_tests_scans_path("betterleaks") / "betterleaks_one_vuln.json").open(
            encoding="utf-8"
        ) as testfile:
            parser = BetterleaksParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("generic-api-key", finding.title)
                self.assertEqual("file.cfg", finding.file_path)

    def test_parse_file_legacy_with_multiple_finding(self):
        with (get_unit_tests_scans_path("betterleaks") / "betterleaks_many_vulns.json").open(
            encoding="utf-8"
        ) as testfile:
            parser = BetterleaksParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(4, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("generic-password", finding.title)
                self.assertEqual("XXXXXXXXXX", finding.file_path)
