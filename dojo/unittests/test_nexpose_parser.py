from django.test import TestCase
from dojo.tools.nexpose.parser import NexposeFullXmlParser
from dojo.models import Test


class TestNexposeParser(TestCase):
    def test_nexpose_parser_has_no_finding(self):
        testfile = open("dojo/unittests/scans/nexpose/no_vuln.xml")
        parser = NexposeFullXmlParser(testfile, Test())
        self.assertEqual(0, len(parser.items))

    def test_nexpose_parser_has_many_finding(self):
        testfile = open("dojo/unittests/scans/nexpose/many_vulns.xml")
        parser = NexposeFullXmlParser(testfile, Test())
        testfile.close()
        self.assertEqual(135, len(parser.items))
