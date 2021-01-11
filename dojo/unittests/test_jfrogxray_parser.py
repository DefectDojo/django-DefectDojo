from django.test import TestCase
from dojo.models import Test
from dojo.tools.jfrogxray.parser import XrayJSONParser


class TestJfrogXrayJSONParser(TestCase):
    def test_parse_without_file_has_no_finding(self):
        parser = XrayJSONParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_one_vuln(self):
        testfile = open("dojo/unittests/scans/jfrogxray/one_vuln.json")
        parser = XrayJSONParser(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(parser.items))
        item = parser.items[0]
        self.assertEquals('debian:stretch:libx11', item.component_name)
        self.assertEquals('2:1.6.4-3', item.component_version)
        self.assertEquals('CVE-2018-14600', item.cve)
        self.assertEquals(787, item.cwe)

    def test_parse_file_with_many_vulns(self):
        testfile = open("dojo/unittests/scans/jfrogxray/many_vulns.json")
        parser = XrayJSONParser(testfile, Test())
        testfile.close()
        self.assertEqual(3, len(parser.items))

    def test_parse_file_with_many_vulns2(self):
        testfile = open("dojo/unittests/scans/jfrogxray/many_vulns2.json")
        parser = XrayJSONParser(testfile, Test())
        testfile.close()
        self.assertEqual(2, len(parser.items))
        item = parser.items[0]
        self.assertEquals('pip', item.component_name)
        self.assertEquals('9.0.1', item.component_version)
        item = parser.items[1]
        self.assertEquals('linux', item.component_name)
        self.assertEquals('4.15.0-88.88', item.component_version)
        self.assertEquals('CVE-2020-14386', item.cve)
        self.assertEquals(787, item.cwe)
        self.assertEquals("AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", item.cvssv3)
