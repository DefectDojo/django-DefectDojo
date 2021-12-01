from ..dojo_test_case import DojoTestCase
from dojo.tools.ccvs.parser import CCVSParser
from dojo.models import Test


class TestCCVSParser(DojoTestCase):
    def test_ccvs_parser_has_no_finding(self):
        testfile = open("unittests/scans/ccvs/no_vuln.json")
        parser = CCVSParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_ccvs_parser_has_one_finding(self):
        testfile = open("unittests/scans/ccvs/one_vuln_one_vendor.json")
        parser = CCVSParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))

    def test_ccvs_parser_has_many_findings(self):
        testfile = open("unittests/scans/ccvs/many_vulns.json")
        parser = CCVSParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(18, len(findings))
