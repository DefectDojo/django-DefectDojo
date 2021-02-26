from django.test import TestCase
from dojo.tools.spotbugs.parser import SpotbugsXMLParser
from dojo.models import Test


class TestSpotbugsParser(TestCase):

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

    def test_find_sast_source_line(self):
        testfile = open("dojo/unittests/scans/spotbugs/many_findings.xml")
        parser = SpotbugsXMLParser(testfile, Test())
        testfile.close()
        finding = parser.items[0]
        self.assertEqual("93", finding.sast_source_line)

    def test_find_sast_source_path(self):
        testfile = open("dojo/unittests/scans/spotbugs/many_findings.xml")
        parser = SpotbugsXMLParser(testfile, Test())
        testfile.close()
        finding = parser.items[0]
        self.assertEqual("securitytest/command/IdentityFunctionCommandInjection.kt", finding.sast_source_file_path)

    def test_find_source_line(self):
        testfile = open("dojo/unittests/scans/spotbugs/many_findings.xml")
        parser = SpotbugsXMLParser(testfile, Test())
        testfile.close()
        finding = parser.items[0]
        self.assertEqual("93", finding.line)

    def test_find_file_path(self):
        testfile = open("dojo/unittests/scans/spotbugs/many_findings.xml")
        parser = SpotbugsXMLParser(testfile, Test())
        testfile.close()
        finding = parser.items[0]
        self.assertEqual("securitytest/command/IdentityFunctionCommandInjection.kt", finding.file_path)
