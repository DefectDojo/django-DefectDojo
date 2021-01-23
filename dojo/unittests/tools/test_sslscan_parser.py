from django.test import TestCase
from dojo.tools.sslscan.parser import SslscanXMLParser
from dojo.models import Test


class TestSslscanParser(TestCase):

    def test_parse_without_file_has_no_findings(self):
        parser = SslscanXMLParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_no_vuln_has_no_findings(self):

        testfile = open("dojo/unittests/scans/sslscan/sslscan_no_vuln.xml")
        parser = SslscanXMLParser(testfile, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        testfile = open("dojo/unittests/scans/sslscan/sslscan_one_vuln.xml")
        parser = SslscanXMLParser(testfile, Test())
        self.assertEqual(1, len(parser.items))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        testfile = open("dojo/unittests/scans/sslscan/sslscan_many_vuln.xml")
        parser = SslscanXMLParser(testfile, Test())
        self.assertEqual(2, len(parser.items))
