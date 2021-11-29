import datetime

from ..dojo_test_case import DojoTestCase
from dojo.models import Test
from dojo.tools.risk_recon.parser import RiskReconParser


class TestRiskReconAPIParser(DojoTestCase):

    def test_api_with_bad_url(self):
        testfile = open("unittests/scans/risk_recon/bad_url.json")
        with self.assertRaises(Exception):
            parser = RiskReconParser()
            findings = parser.get_findings(testfile, Test())

    def test_api_with_bad_key(self):
        testfile = open("unittests/scans/risk_recon/bad_key.json")
        with self.assertRaises(Exception):
            parser = RiskReconParser()
            findings = parser.get_findings(testfile, Test())

    def test_parser_without_api(self):
        testfile = open("unittests/scans/risk_recon/findings.json")
        parser = RiskReconParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(2, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual(datetime.date(2017, 3, 17), finding.date.date())
            self.assertEqual("ff2bbdbfc2b6fddc061ed96b1fasfwefb", finding.unique_id_from_tool)
        with self.subTest(i=1):
            finding = findings[1]
            self.assertEqual(datetime.date(2017, 3, 17), finding.date.date())
            self.assertEqual("ff2bbdbfc2b6gsrgwergwe6b1fasfwefb", finding.unique_id_from_tool)
