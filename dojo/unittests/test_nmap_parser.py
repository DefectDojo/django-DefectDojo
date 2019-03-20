from django.test import TestCase
from dojo.tools.nmap.parser import NmapXMLParser
from dojo.models import Test


class TestNmapParser(TestCase):

    def test_parse_without_file_has_no_findings(self):
        parser = NmapXMLParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_no_open_ports_has_no_findings(self):

        testfile = open("dojo/unittests/scans/nmap_sample/nmap_0port.xml")
        parser = NmapXMLParser(testfile, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_single_open_ports_has_single_finding(self):
        testfile = open("dojo/unittests/scans/nmap_sample/nmap_1port.xml")
        parser = NmapXMLParser(testfile, Test())
        self.assertEqual(1, len(parser.items))

    def test_parse_file_with_multiple_open_ports_has_multiple_finding(self):
        testfile = open("dojo/unittests/scans/nmap_sample/nmap_multiple_port.xml")
        parser = NmapXMLParser(testfile, Test())
        self.assertEqual(13, len(parser.items))
