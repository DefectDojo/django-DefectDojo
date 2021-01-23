from django.test import TestCase
from dojo.models import Test
from dojo.tools.sonatype.parser import SonatypeJSONParser


class TestSonatypeJSONParser(TestCase):
    def test_parse_file_with_one_vuln(self):
        testfile = open("dojo/unittests/scans/sonatype/one_vuln.json")
        parser = SonatypeJSONParser(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(parser.items))

    def test_parse_file_with_many_vulns(self):
        testfile = open("dojo/unittests/scans/sonatype/many_vulns.json")
        parser = SonatypeJSONParser(testfile, Test())
        testfile.close()
        self.assertEqual(3, len(parser.items))

    def test_parse_file_with_long_file_path(self):
        testfile = open("dojo/unittests/scans/sonatype/long_file_path.json")
        parser = SonatypeJSONParser(testfile, Test())
        testfile.close()
        self.assertEqual(2, len(parser.items))
