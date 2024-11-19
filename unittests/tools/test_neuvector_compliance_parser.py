from os import path
from pathlib import Path

from dojo.models import Test
from dojo.tools.neuvector_compliance.parser import NeuVectorComplianceParser
from unittests.dojo_test_case import DojoTestCase


class TestNeuVectorComplianceParser(DojoTestCase):
    def test_parse_file_with_no_vuln(self):
        testfile = open(path.join(Path(__file__).parent, "../scans/neuvector_compliance/no_vuln.json"), encoding="utf-8")
        parser = NeuVectorComplianceParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln(self):
        testfile = open(path.join(Path(__file__).parent, "../scans/neuvector_compliance/one_vuln.json"), encoding="utf-8")
        parser = NeuVectorComplianceParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        self.assertEqual("docker_D.1.1.11", findings[0].vuln_id_from_tool)

    def test_parse_file_with_many_vulns(self):
        testfile = open(path.join(Path(__file__).parent, "../scans/neuvector_compliance/many_vulns.json"), encoding="utf-8")
        parser = NeuVectorComplianceParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(6, len(findings))
