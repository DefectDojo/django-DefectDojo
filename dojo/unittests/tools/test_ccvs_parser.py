from django.test import TestCase
from dojo.tools.ccvs.parser import CCVSReportParser
from dojo.models import Test


class TestCCVSReportParser(TestCase):
    def test_ccvs_parser_has_no_finding(self):
        testfile = open("dojo/unittests/scans/ccvs/no_vuln.json")
        parser = CCVSReportParser(testfile, Test())
        self.assertEqual(0, len(parser.items))

    def test_ccvs_parser_has_one_finding(self):
        testfile = open("dojo/unittests/scans/ccvs/one_vuln_one_vendor.json")
        parser = CCVSReportParser(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(parser.items))

    def test_ccvs_parser_has_many_findings(self):
        testfile = open("dojo/unittests/scans/ccvs/many_vulns.json")
        parser = CCVSReportParser(testfile, Test())
        testfile.close()
        self.assertEqual(18, len(parser.items))
