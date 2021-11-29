from ..dojo_test_case import DojoTestCase, get_unit_tests_path
from dojo.tools.blackduck.parser import BlackduckParser
from dojo.models import Test
from pathlib import Path


class TestBlackduckHubParser(DojoTestCase):
    def test_blackduck_csv_parser_has_no_finding(self):
        testfile = Path(get_unit_tests_path() + "/scans/blackduck/no_vuln.csv")
        parser = BlackduckParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_blackduck_csv_parser_has_one_finding(self):
        testfile = Path(get_unit_tests_path() + "/scans/blackduck/one_vuln.csv")
        parser = BlackduckParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_blackduck_csv_parser_has_many_findings(self):
        testfile = Path(get_unit_tests_path() + "/scans/blackduck/many_vulns.csv")
        parser = BlackduckParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(24, len(findings))

    def test_blackduck_csv_parser_new_format_has_many_findings(self):
        testfile = Path(get_unit_tests_path() + "/scans/blackduck/many_vulns_new_format.csv")
        parser = BlackduckParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(9, len(findings))

    def test_blackduck_enhanced_has_many_findings(self):
        testfile = Path(
            get_unit_tests_path() + "/scans/blackduck/blackduck_enhanced_py3_unittest.zip"
        )
        parser = BlackduckParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(11, len(findings))

    def test_blackduck_enhanced_zip_upload(self):
        testfile = Path(
            get_unit_tests_path() + "/scans/blackduck/blackduck_enhanced_py3_unittest_v2.zip"
        )
        parser = BlackduckParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(11, len(findings))
