from django.test import TestCase
from dojo.tools.spotbugs.parser import SpotbugsXMLParser
from dojo.models import Test


class TestSpotbugsXMLParser(TestCase):

    def test_no_findings(self):
        testfile = open("dojo/unittests/scans/spotbugs/no_finding.xml")
        parser = SpotbugsXMLParser(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(parser.items))

    def test_parse_many_finding(self):
        testfile = open("dojo/unittests/scans/spotbugs/many_findings.xml")
        parser = SpotbugsXMLParser(testfile, Test())
        testfile.close()
        self.assertEqual(81, len(parser.items))
