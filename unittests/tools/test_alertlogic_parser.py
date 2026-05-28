from dojo.models import Test
from dojo.tools.alertlogic.parser import AlertlogicParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestAlertlogicParser(DojoTestCase):

    def test_get_scan_types(self):
        self.assertEqual(["Alert Logic Scan"], AlertlogicParser().get_scan_types())

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("alertlogic") / "no_vuln.csv").open(encoding="utf-8") as testfile:
            findings = AlertlogicParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("alertlogic") / "one_vuln.csv").open(encoding="utf-8") as testfile:
            findings = AlertlogicParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("alertlogic") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            findings = AlertlogicParser().get_findings(testfile, Test())
            self.assertEqual(7, len(findings))
