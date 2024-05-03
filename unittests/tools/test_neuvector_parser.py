from os import path
from ..dojo_test_case import DojoTestCase
from dojo.models import Test
from dojo.tools.neuvector.parser import NeuVectorParser


class TestNeuVectorParser(DojoTestCase):
    def test_parse_file_with_no_vuln(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/neuvector/no_vuln.json"))
        parser = NeuVectorParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/neuvector/one_vuln.json"))
        parser = NeuVectorParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        self.assertEqual(1, len(findings[0].unsaved_vulnerability_ids))
        self.assertEqual("CVE-2015-8356", findings[0].unsaved_vulnerability_ids[0])

    def test_parse_file_with_many_vulns(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/neuvector/many_vulns.json"))
        parser = NeuVectorParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(2, len(findings))
