from os import path
from ..dojo_test_case import DojoTestCase
from dojo.models import Test
from dojo.tools.twistlock.parser import TwistlockParser


class TestTwistlockParser(DojoTestCase):
    def test_parse_file_with_no_vuln(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/twistlock/no_vuln.json"))
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/twistlock/one_vuln.json"))
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        self.assertEqual(1, len(findings[0].unsaved_vulnerability_ids))
        self.assertEqual("CVE-2013-7459", findings[0].unsaved_vulnerability_ids[0])

    def test_parse_file_with_many_vulns(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/twistlock/many_vulns.json"))
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(5, len(findings))

    def test_parse_file_which_contain_packages_info(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/twistlock/findings_include_packages.json"))
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(4, len(findings))

    def test_parse_file_prisma_twistlock_images_no_vuln(self):
        testfile = open(
            path.join(path.dirname(__file__), "../scans/twistlock/scan_report_prisma_twistlock_images_no_vuln.csv")
        )
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parse_file_prisma_twistlock_images_four_vulns(self):
        testfile = open(
            path.join(path.dirname(__file__), "../scans/twistlock/scan_report_prisma_twistlock_images_four_vulns.csv")
        )
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(4, len(findings))
        self.assertEqual(1, len(findings[0].unsaved_vulnerability_ids))
        self.assertEqual("CVE-2020-24977", findings[0].unsaved_vulnerability_ids[0])

    def test_parse_file_prisma_twistlock_images_long_package_name(self):
        testfile = open(
            path.join(
                path.dirname(__file__), "../scans/twistlock/scan_report_prisma_twistlock_images_long_package_name.csv"
            )
        )
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
