from django.test import TestCase
from dojo.tools.nmap.parser import NmapParser
from dojo.models import Test


class TestNmapParser(TestCase):

    def test_parse_file_with_no_open_ports_has_no_findings(self):
        testfile = open("dojo/unittests/scans/nmap/nmap_0port.xml")
        parser = NmapParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_single_open_ports_has_single_finding(self):
        testfile = open("dojo/unittests/scans/nmap/nmap_1port.xml")
        parser = NmapParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_open_ports_has_multiple_finding(self):
        testfile = open("dojo/unittests/scans/nmap/nmap_multiple_port.xml")
        parser = NmapParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(13, len(findings))

    def test_parse_file_with_script_vulner(self):
        testfile = open("dojo/unittests/scans/nmap/nmap_script_vulners.xml")
        parser = NmapParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(3, len(findings))

        self.assertEqual("Medium", findings[0].severity)
        self.assertEqual("CVE-2018-15919", findings[0].cve)
        self.assertEqual("openssh", findings[0].component_name)
        self.assertEqual("7.4", findings[0].component_version)

        self.assertEqual("Medium", findings[1].severity)
        self.assertEqual("CVE-2017-15906", findings[1].cve)
        self.assertEqual("openssh", findings[1].component_name)
        self.assertEqual("7.4", findings[1].component_version)

        self.assertEqual("Info", findings[2].severity)
