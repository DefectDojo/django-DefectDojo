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
        self.assertEqual(17, len(findings))
        # vuln 1
        finding = findings[0]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("TCP Sequence Number Approximation Vulnerability", finding.title)
        self.assertEqual("CVE-2004-0230", finding.cve)
        self.assertEqual(3, len(finding.unsaved_endpoints))
        self.assertIn("https://www.securityfocus.com/bid/10183", finding.references)  # BID: 10183
        self.assertIn("https://www.kb.cert.org/vuls/id/415294.html", finding.references)  # CERT-VN: 415294
        self.assertIn("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0230", finding.references)  # CVE: CVE-2004-0230
        # vuln 2
        finding = findings[2]
        self.assertEqual("Low", finding.severity)
        self.assertEqual("TCP timestamp response", finding.title)
        self.assertIsNone(finding.cve)
        self.assertEqual(5, len(finding.unsaved_endpoints))
        # vuln 2 - endpoint
        endpoint = finding.unsaved_endpoints[0]
        self.assertIsNone(endpoint.port)
        self.assertIsNone(endpoint.protocol)
        # vuln 3
        finding = findings[3]
        self.assertEqual("Default SSH password: root password \"root\"", finding.title)
        self.assertEqual(1, len(finding.unsaved_endpoints))
        # vuln 3 - endpoint
        endpoint = finding.unsaved_endpoints[0]
        self.assertEqual(22, endpoint.port)
        self.assertEqual("ssh", endpoint.protocol)
        # vuln 16
        finding = findings[16]
        self.assertEqual("TLS/SSL Server Supports DES and IDEA Cipher Suites", finding.title)
        self.assertEqual(1, len(finding.unsaved_endpoints))
        # vuln 16 - endpoint
        endpoint = finding.unsaved_endpoints[0]
        self.assertEqual(443, endpoint.port)
        self.assertIsNone(endpoint.protocol)

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
        self.assertEqual(4, len(finding.unsaved_endpoints))
        # vuln 1
        finding = findings[1]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("No password for Grub", finding.title)
        self.assertIsNone(finding.cve)
        self.assertEqual(4, len(finding.unsaved_endpoints))
        # vuln 2
        finding = findings[2]
        self.assertEqual("Low", finding.severity)
        self.assertEqual("User home directory mode unsafe", finding.title)
        self.assertIsNone(finding.cve)
        self.assertEqual(16, len(finding.unsaved_endpoints))

    def test_nexpose_parser_dns(self):
        testfile = open("dojo/unittests/scans/nexpose/dns.xml")
        parser = NexposeParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(3, len(findings))
        # vuln 0
        finding = findings[0]
        self.assertEqual("DNS server allows cache snooping", finding.title)
        self.assertEqual(2, len(finding.unsaved_endpoints))
        self.assertEqual('dns', str(finding.unsaved_endpoints[0].protocol))
        self.assertEqual('tcp', str(finding.unsaved_endpoints[0].fragment))
        self.assertEqual('dns', str(finding.unsaved_endpoints[1].protocol))
        self.assertEqual('udp', str(finding.unsaved_endpoints[1].fragment))
        # TODO uncomment these lines when PR #4188 will be done
        # self.assertEqual('dns://192.168.1.1#tcp', str(finding.unsaved_endpoints[0]))
        # self.assertEqual('dns://192.168.1.1#udp', str(finding.unsaved_endpoints[1]))

        # vuln 1
        finding = findings[1]
        self.assertEqual("Nameserver Processes Recursive Queries", finding.title)
        self.assertEqual(2, len(finding.unsaved_endpoints))
        self.assertEqual('dns', str(finding.unsaved_endpoints[0].protocol))
        self.assertEqual('tcp', str(finding.unsaved_endpoints[0].fragment))
        self.assertEqual('dns', str(finding.unsaved_endpoints[1].protocol))
        self.assertEqual('udp', str(finding.unsaved_endpoints[1].fragment))
        # TODO uncomment these lines when PR #4188 will be done
        # self.assertEqual('dns://192.168.1.1#tcp', str(finding.unsaved_endpoints[0]))
        # self.assertEqual('dns://192.168.1.1#udp', str(finding.unsaved_endpoints[1]))

        # vuln 2
        finding = findings[2]
        self.assertEqual("DNS Traffic Amplification", finding.title)
        self.assertEqual(1, len(finding.unsaved_endpoints))
        self.assertEqual('dns', str(finding.unsaved_endpoints[0].protocol))
        self.assertEqual('udp', str(finding.unsaved_endpoints[0].fragment))
        # TODO uncomment this line when PR #4188 will be done
        # self.assertEqual('dns://192.168.1.1#udp', str(finding.unsaved_endpoints[0]))
