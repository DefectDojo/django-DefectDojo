from os import path

from django.test import TestCase
from dojo.models import Test
from dojo.tools.risk_recon.parser import RiskReconParser


class TestRiskReconAPIParser(TestCase):

    def test_api_with_bad_url(self):
        testfile = open(path.join(path.dirname(__file__), "scans/risk_recon/bad_url.json"))
        with self.assertRaises(Exception):
            parser = RiskReconParser()
            findings = parser.get_findings(testfile, Test())

    def test_api_with_bad_key(self):
        testfile = open(path.join(path.dirname(__file__), "scans/risk_recon/bad_key.json"))
        with self.assertRaises(Exception):
            parser = RiskReconParser()
            findings = parser.get_findings(testfile, Test())

    def test_parser_without_api(self):
        testfile = open(path.join(path.dirname(__file__), "scans/risk_recon/findings.json"))
        parser = RiskReconParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(2, len(findings))
