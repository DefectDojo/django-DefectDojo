import datetime

import requests

from dojo.models import Test
from dojo.tools.risk_recon.parser import RiskReconParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestRiskReconAPIParser(DojoTestCase):

    def test_api_with_bad_url(self):
        with (get_unit_tests_scans_path("risk_recon") / "bad_url.json").open(encoding="utf-8") as testfile, \
          self.assertRaises(requests.exceptions.ConnectionError):
            parser = RiskReconParser()
            parser.get_findings(testfile, Test())

    def test_api_with_bad_key(self):
        with (get_unit_tests_scans_path("risk_recon") / "bad_key.json").open(encoding="utf-8") as testfile, \
          self.assertRaises(Exception):  # noqa: B017 #TODO: Exception from tools/risk_recon/api.py --> def map_toes(self)
            parser = RiskReconParser()
            parser.get_findings(testfile, Test())

    def test_parser_without_api(self):
        with (get_unit_tests_scans_path("risk_recon") / "findings.json").open(encoding="utf-8") as testfile:
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
