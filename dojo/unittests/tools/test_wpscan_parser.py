import datetime

from django.test import TestCase

from dojo.models import Test
from dojo.tools.wpscan.parser import WpscanParser


class TestWpscanParser(TestCase):

    def test_parse_file_empty(self):
        """Report from the tool wich have no data"""
        testfile = open("dojo/unittests/scans/wpscan/empty.json")
        parser = WpscanParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_exemple(self):
        testfile = open("dojo/unittests/scans/wpscan/sample.json")
        parser = WpscanParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(4, len(findings))
        finding = findings[0]
        self.assertIsNone(finding.unique_id_from_tool)  # interesting findings are not vlunerability
        self.assertEqual("Info", finding.severity)  # it is not a vulnerability so severity should be 'Info'
        self.assertEqual("Interesting finding: Headers", finding.title)
        self.assertEqual(datetime.datetime(2021, 3, 26, 11, 50, 50), finding.date)

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/wpscan/wordpress_no_vuln.json")
        parser = WpscanParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(7, len(findings))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        testfile = open("dojo/unittests/scans/wpscan/wordpress_one_vuln.json")
        parser = WpscanParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(8, len(findings))
        finding = findings[0]
        self.assertEqual("8873", finding.unique_id_from_tool)
        self.assertNotEqual("Info", finding.severity)  # it is a vulnerability so not 'Info'
        self.assertEqual("YouTube Embed <= 11.8.1 - Cross-Site Request Forgery (CSRF)", finding.title)
        self.assertEqual(datetime.datetime(2019, 7, 2, 19, 11, 16), finding.date)

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        testfile = open("dojo/unittests/scans/wpscan/wordpress_many_vuln.json")
        parser = WpscanParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(8, len(findings))
        finding = findings[0]
        self.assertEqual("8873", finding.unique_id_from_tool)
        self.assertNotEqual("Info", finding.severity)  # it is a vulnerability so not 'Info'
        self.assertEqual("YouTube Embed <= 11.8.1 - Cross-Site Request Forgery (CSRF)", finding.title)
        self.assertEqual(datetime.datetime(2019, 7, 2, 19, 11, 16), finding.date)

    def test_parse_file_with_multiple_vuln(self):
        testfile = open("dojo/unittests/scans/wpscan/wpscan.json")
        parser = WpscanParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(6, len(findings))
        finding = findings[0]
        self.assertEqual("7391118e-eef5-4ff8-a8ea-f6b65f442c63", finding.unique_id_from_tool)
        self.assertNotEqual("Info", finding.severity)  # it is a vulnerability so not 'Info'
        self.assertEqual("Contact Form 7 < 5.3.2 - Unrestricted File Upload", finding.title)
        self.assertEqual("CVE-2020-35489", finding.cve)
        self.assertEqual(datetime.datetime(2021, 3, 17, 12, 21, 6), finding.date)
        #
        finding = findings[4]
        self.assertIsNone(finding.unique_id_from_tool)  # interesting findings are not vlunerability
        self.assertEqual("Info", finding.severity)  # it is not a vulnerability so severity should be 'Info'
        self.assertEqual("Interesting finding: WordPress readme found: http://example/readme.html", finding.title)
        self.assertEqual(datetime.datetime(2021, 3, 17, 12, 21, 6), finding.date)
