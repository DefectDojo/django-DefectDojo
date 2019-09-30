from django.test import TestCase
from dojo.tools.blackduck.parser import BlackduckHubCSVParser
from dojo.models import Test
from pathlib import Path


class TestBlackduckHubParser(TestCase):
    # def test_blackduck_csv_parser_has_no_finding(self):
    #     testfile = open("dojo/unittests/scans/blackduck/no_vuln.csv")
    #     parser = BlackduckHubCSVParser(testfile, Test())
    #     self.assertEqual(0, len(parser.items))

    # def test_blackduck_csv_parser_has_one_finding(self):
    #     testfile = open("dojo/unittests/scans/blackduck/one_vuln.csv")
    #     parser = BlackduckHubCSVParser(testfile, Test())
    #     testfile.close()
    #     self.assertEqual(1, len(parser.items))

    # def test_blackduck_csv_parser_has_many_findings(self):
    #     testfile = open("dojo/unittests/scans/blackduck/many_vulns.csv")
    #     parser = BlackduckHubCSVParser(testfile, Test())
    #     testfile.close()
    #     self.assertEqual(24, len(parser.items))

    def test_blackduck_enhanced_has_many_findings(self):
        testfile = Path("dojo/unittests/scans/blackduck/blackduck_enhanced_py3_unittest.zip")
        parser = BlackduckHubCSVParser(testfile, Test())
        self.assertEqual(11, len(parser.items))
