from django.test import TestCase
from dojo.models import Test
from dojo.tools.jfrogxray.parser import XrayJSONParser


class TestJfrogXrayJSONParser(TestCase):
    def test_parse_file_with_one_vuln(self):
        testfile = open("dojo/unittests/scans/jfrogxray/one_vuln.json")
        parser = XrayJSONParser(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(parser.items))

    def test_parse_file_with_many_vulns(self):
        testfile = open("dojo/unittests/scans/jfrogxray/many_vulns.json")
        parser = XrayJSONParser(testfile, Test())
        testfile.close()
        self.assertEqual(3, len(parser.items))
