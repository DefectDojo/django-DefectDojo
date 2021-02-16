from django.test import TestCase
from dojo.tools.nexpose.parser import NexposeParser
from dojo.models import Test, Engagement, Product


class TestNexposeParser(TestCase):

    def test_nexpose_parser_has_no_finding(self):
        testfile = open("dojo/unittests/scans/nexpose/no_vuln.xml")
        parser = NexposeParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_nexpose_parser_has_many_finding(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        testfile = open("dojo/unittests/scans/nexpose/many_vulns.xml")
        parser = NexposeParser()
        findings = parser.get_findings(testfile, test)
        testfile.close()
        self.assertEqual(13, len(findings))
        # vuln 1
        finding = findings[0]
        self.assertEqual("Critical", finding.severity)
        self.assertEqual("Default SSH password: root password \"root\"", finding.title)
        self.assertIsNone(finding.cve)
        self.assertEqual(1, len(finding.unsaved_endpoints))
        # vuln 2
        finding = findings[2]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("Missing HttpOnly Flag From Cookie", finding.title)
        self.assertIsNone(finding.cve)
        self.assertEqual(1, len(finding.unsaved_endpoints))

    def test_nexpose_parser_tests_outside_endpoint(self):
        testfile = open("dojo/unittests/scans/nexpose/report_auth.xml")
        parser = NexposeParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(4, len(findings))
        # vuln 0
        finding = findings[0]
        self.assertEqual("High", finding.severity)
        self.assertEqual("ICMP redirection enabled", finding.title)
        self.assertIsNone(finding.cve)
        # vuln 1
        finding = findings[1]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("No password for Grub", finding.title)
        self.assertIsNone(finding.cve)
        # vuln 2
        finding = findings[2]
        self.assertEqual("Low", finding.severity)
        self.assertEqual("User home directory mode unsafe", finding.title)
        self.assertIsNone(finding.cve)
