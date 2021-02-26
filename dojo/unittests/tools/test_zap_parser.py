from django.test import TestCase
from dojo.tools.zap.parser import ZapParser
from dojo.models import Test, Engagement, Product


class TestZapParser(TestCase):
    def get_test(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        return test

    def test_parse_no_findings(self):
        testfile = open("dojo/unittests/scans/zap/empty_2.9.0.xml")
        parser = ZapParser()
        findings = parser.get_findings(testfile, self.get_test())
        self.assertEqual(0, len(findings))

    def test_parse_some_findings(self):
        testfile = open("dojo/unittests/scans/zap/some_2.9.0.xml")
        parser = ZapParser()
        findings = parser.get_findings(testfile, self.get_test())
        self.assertEqual(7, len(findings))

    def test_parse_some_findings_0(self):
        testfile = open("dojo/unittests/scans/zap/0_zap_sample.xml")
        parser = ZapParser()
        findings = parser.get_findings(testfile, self.get_test())
        self.assertIsInstance(findings, list)

    def test_parse_some_findings_1(self):
        testfile = open("dojo/unittests/scans/zap/1_zap_sample_0_and_new_absent.xml")
        parser = ZapParser()
        findings = parser.get_findings(testfile, self.get_test())
        self.assertIsInstance(findings, list)

    def test_parse_some_findings_2(self):
        testfile = open("dojo/unittests/scans/zap/2_zap_sample_0_and_new_endpoint.xml")
        parser = ZapParser()
        findings = parser.get_findings(testfile, self.get_test())
        self.assertIsInstance(findings, list)

    def test_parse_some_findings_3(self):
        testfile = open(
            "dojo/unittests/scans/zap/3_zap_sampl_0_and_different_severities.xml"
        )
        parser = ZapParser()
        findings = parser.get_findings(testfile, self.get_test())
        self.assertIsInstance(findings, list)

    def test_parse_some_findings_5(self):
        testfile = open("dojo/unittests/scans/zap/5_zap_sample_one.xml")
        parser = ZapParser()
        findings = parser.get_findings(testfile, self.get_test())
        self.assertIsInstance(findings, list)
