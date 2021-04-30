from django.test import TestCase
from dojo.models import Test
from dojo.tools.zap.parser import ZapParser


class TestZapParser(TestCase):

    def test_parse_no_findings(self):
        testfile = open("dojo/unittests/scans/zap/empty_2.9.0.xml")
        parser = ZapParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_some_findings(self):
        testfile = open("dojo/unittests/scans/zap/some_2.9.0.xml")
        parser = ZapParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(7, len(findings))

    def test_parse_some_findings_0(self):
        testfile = open("dojo/unittests/scans/zap/0_zap_sample.xml")
        parser = ZapParser()
        findings = parser.get_findings(testfile, Test())
        self.assertIsInstance(findings, list)

    def test_parse_some_findings_1(self):
        testfile = open("dojo/unittests/scans/zap/1_zap_sample_0_and_new_absent.xml")
        parser = ZapParser()
        findings = parser.get_findings(testfile, Test())
        self.assertIsInstance(findings, list)

    def test_parse_some_findings_2(self):
        testfile = open("dojo/unittests/scans/zap/2_zap_sample_0_and_new_endpoint.xml")
        parser = ZapParser()
        findings = parser.get_findings(testfile, Test())
        self.assertIsInstance(findings, list)

    def test_parse_some_findings_3(self):
        testfile = open(
            "dojo/unittests/scans/zap/3_zap_sampl_0_and_different_severities.xml"
        )
        parser = ZapParser()
        findings = parser.get_findings(testfile, Test())
        self.assertIsInstance(findings, list)

    def test_parse_some_findings_5(self):
        testfile = open("dojo/unittests/scans/zap/5_zap_sample_one.xml")
        parser = ZapParser()
        findings = parser.get_findings(testfile, Test())
        self.assertIsInstance(findings, list)

    def test_parse_issue4360(self):
        """Report from GitHub issue 4360
        see: https://github.com/DefectDojo/django-DefectDojo/issues/4360
        """
        testfile = open("dojo/unittests/scans/zap/dvwa_baseline_dojo.xml")
        parser = ZapParser()
        findings = parser.get_findings(testfile, Test())
        self.assertIsInstance(findings, list)
        self.assertEqual(19, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("X-Frame-Options Header Not Set", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(12, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual("http://172.17.0.2:80", endpoint.host)
            endpoint = finding.unsaved_endpoints[1]
            self.assertEqual("http", endpoint.protocol)
            self.assertEqual("172.17.0.2", endpoint.host)
            self.assertEqual('/vulnerabilities/brute/', endpoint.path)
        with self.subTest(i=18):
            finding = findings[18]
            self.assertEqual("Private IP Disclosure", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual(4, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
