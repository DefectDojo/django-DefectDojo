from django.test import TestCase
from dojo.models import Test
from dojo.tools.risk_recon.parser import RiskReconParser


class TestRiskReconAPIParser(TestCase):
    def test_parser_with_no_file(self):
        parser = RiskReconParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_api_with_bad_url(self):
        testfile = open("dojo/unittests/scans/risk_recon/bad_url.json")
        with self.assertRaises(Exception):
            parser = RiskReconParser(testfile, Test())

    def test_api_with_bad_key(self):
        testfile = open("dojo/unittests/scans/risk_recon/bad_key.json")
        with self.assertRaises(Exception):
            parser = RiskReconParser(testfile, Test())

    def test_parser_without_api(self):
        testfile = open("dojo/unittests/scans/risk_recon/findings.json")
        parser = RiskReconParser(testfile, Test())
        self.assertEqual(2, len(parser.items))
