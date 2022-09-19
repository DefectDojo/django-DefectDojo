from ..dojo_test_case import DojoTestCase
from dojo.tools.anchore_engine.parser import AnchoreEngineParser
from dojo.models import Test


class TestAnchoreCTLParser(DojoTestCase):
    def test_anchore_engine_parser_has_no_finding(self):
        testfile = open("unittests/scans/anchoreCTL/no_vuln.json")
        parser = AnchoreEngineParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_anchore_engine_parser_has_one_finding(self):
        testfile = open("unittests/scans/anchoreCTL/one_vuln.json")
        parser = AnchoreEngineParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))

    def test_anchore_engine_parser_has_many_findings(self):
        testfile = open("unittests/scans/anchoreCTL/many_vulns.json")
        parser = AnchoreEngineParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(23, len(findings))
