from django.test import TestCase
from dojo.tools.anchore_engine.parser import AnchoreEngineParser
from dojo.models import Test


class TestAnchoreEngineParser(TestCase):
    def test_anchore_engine_parser_has_no_finding(self):
        testfile = open("dojo/unittests/scans/anchore/no_vuln.json")
        parser = AnchoreEngineParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_anchore_engine_parser_has_one_finding(self):
        testfile = open("dojo/unittests/scans/anchore/one_vuln.json")
        parser = AnchoreEngineParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))

    def test_anchore_engine_parser_has_many_findings(self):
        testfile = open("dojo/unittests/scans/anchore/many_vulns.json")
        parser = AnchoreEngineParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(23, len(findings))

    def test_anchore_engine_parser_has_many_findings_2_4_1(self):
        testfile = open("dojo/unittests/scans/anchore/many_vulns_2.4.1.json")
        parser = AnchoreEngineParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(51, len(findings))
