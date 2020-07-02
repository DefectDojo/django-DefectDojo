from django.test import TestCase
from dojo.tools.nexpose.parser import NexposeFullXmlParser
from dojo.models import Test


class TestNexposeParser(TestCase):
    def test_nexpose_parser_has_no_finding(self):
        parser = NexposeFullXmlParser(None, Test())
        self.assertEqual(0, int(parser.items))

    def test_nexpose_parser_has_one_finding(self):
        testfile = open("dojo/unittests/scans/nexpose/one_vuln.xml")
        parser = NexposeFullXmlParser(testfile, Test())
        testfile.close()
        self.assertEqual(1, int(parser.items))

    def test_nexpose_parser_has_many_finding(self):
        testfile = open("dojo/unittests/scans/nexpose/many_vulns.xml")
        parser = NexposeFullXmlParser(testfile, Test())
        testfile.close()
        self.assertEqual(24, int(parser.items))
