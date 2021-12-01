from ..dojo_test_case import DojoTestCase
from dojo.tools.anchore_engine.parser import AnchoreEngineParser
from dojo.models import Test


class TestAnchoreEngineParser(DojoTestCase):
    def test_anchore_engine_parser_has_no_finding(self):
        testfile = open("unittests/scans/anchore/no_vuln.json")
        parser = AnchoreEngineParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_anchore_engine_parser_has_one_finding(self):
        testfile = open("unittests/scans/anchore/one_vuln.json")
        parser = AnchoreEngineParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))

    def test_anchore_engine_parser_has_many_findings(self):
        testfile = open("unittests/scans/anchore/many_vulns.json")
        parser = AnchoreEngineParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(23, len(findings))

    def test_anchore_engine_parser_has_many_findings_2_4_1(self):
        testfile = open("unittests/scans/anchore/many_vulns_2.4.1.json")
        parser = AnchoreEngineParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(51, len(findings))
        finding = findings[50]
        self.assertEqual("CVE-2020-13776", finding.vuln_id_from_tool)
        self.assertEqual('systemd-pam', finding.component_name)
        self.assertEqual('239-41.el8_3.1', finding.component_version)
        self.assertEqual(6.7, finding.cvssv3_score)
