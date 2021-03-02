from django.test import TestCase
from dojo.tools.spotbugs.parser import SpotbugsXMLParser
from dojo.models import Test


class TestSpotbugsParser(TestCase):

    def test_no_findings(self):
        parser = SpotbugsXMLParser()
        parser.get_findings("dojo/unittests/scans/spotbugs/no_finding.xml",Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_many_finding(self):
        parser = SpotbugsXMLParser()
        parser.get_findings("dojo/unittests/scans/spotbugs/many_findings.xml",Test())
        self.assertEqual(81, len(parser.items))

    def test_find_sast_source_line(self):
        parser = SpotbugsXMLParser()
        parser.get_findings("dojo/unittests/scans/spotbugs/many_findings.xml",Test())
        test_finding = parser.items[0]
        self.assertEqual(95, test_finding.sast_source_line)

    def test_find_sast_source_path(self):
        parser = SpotbugsXMLParser()
        parser.get_findings("dojo/unittests/scans/spotbugs/many_findings.xml",Test())
        test_finding = parser.items[0]
        self.assertEqual("securitytest/command/IdentityFunctionCommandInjection.kt", test_finding.sast_source_file_path)

    def test_find_source_line(self):
        parser = SpotbugsXMLParser()
        parser.get_findings("dojo/unittests/scans/spotbugs/many_findings.xml",Test())
        test_finding = parser.items[0]
        self.assertEqual(95, test_finding.line)

    def test_find_file_path(self):
        parser = SpotbugsXMLParser()
        parser.get_findings("dojo/unittests/scans/spotbugs/many_findings.xml",Test())
        test_finding = parser.items[0]
        self.assertEqual("securitytest/command/IdentityFunctionCommandInjection.kt", test_finding.file_path)
