from django.test import TestCase
from dojo.tools.nexpose.parser import NexposeFullXmlParser
from dojo.models import Test


class TestNexposeParser(TestCase):
    def test_nexpose_parser_has_no_finding(self):
        testfile = open("dojo/unittests/scans/nexpose/no_vuln.xml")
        parser = NexposeFullXmlParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_nexpose_parser_has_many_finding(self):
        testfile = open("dojo/unittests/scans/nexpose/many_vulns.xml")
        parser = NexposeFullXmlParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(125, len(findings))
