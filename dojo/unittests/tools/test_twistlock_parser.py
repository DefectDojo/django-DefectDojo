from django.test import TestCase
from dojo.models import Test
from dojo.tools.twistlock.parser import TwistlockParser


class TestTwistlockParser(TestCase):
    def test_parse_file_with_no_vuln(self):
        testfile = open("dojo/unittests/scans/twistlock/no_vuln.json")
        parser = TwistlockParser(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_one_vuln(self):
        testfile = open("dojo/unittests/scans/twistlock/one_vuln.json")
        parser = TwistlockParser(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(parser.items))

    def test_parse_file_with_many_vulns(self):
        testfile = open("dojo/unittests/scans/twistlock/many_vulns.json")
        parser = TwistlockParser(testfile, Test())
        testfile.close()
        self.assertEqual(5, len(parser.items))

    def test_parse_file_which_contain_packages_info(self):
        testfile = open("dojo/unittests/scans/twistlock/findings_include_packages.json")
        parser = TwistlockParser(testfile, Test())
        testfile.close()
        self.assertEqual(4, len(parser.items))

    def test_parse_file_prisma_twistlock_images_no_vuln(self):
        testfile = open("dojo/unittests/scans/twistlock/scan_report_prisma_twistlock_images_no_vuln.csv")
        parser = TwistlockParser(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(parser.items))

    def test_parse_file_prisma_twistlock_images_four_vulns(self):
        testfile = open("dojo/unittests/scans/twistlock/scan_report_prisma_twistlock_images_four_vulns.csv")
        parser = TwistlockParser(testfile, Test())
        testfile.close()
        self.assertEqual(4, len(parser.items))

    def test_parse_file_prisma_twistlock_images_long_package_name(self):
        testfile = open("dojo/unittests/scans/twistlock/scan_report_prisma_twistlock_images_long_package_name.csv")
        parser = TwistlockParser(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(parser.items))
