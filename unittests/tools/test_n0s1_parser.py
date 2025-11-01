
import json

from dojo.models import Test, Test_Type
from dojo.tools.n0s1.parser import N0s1Parser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestN0s1Parser(DojoTestCase):

    def test_n0s1_parser_with_multiple_findings(self):
        with (get_unit_tests_scans_path("n0s1") / "many_findings.json").open(encoding="utf-8") as testfile:
            parser = N0s1Parser()
            test_type = Test_Type(name="n0s1 Scanner")
            test = Test(test_type=test_type)
            findings = parser.get_findings(testfile, test)
            self.assertEqual(17, len(findings))
            finding = findings[0]
            self.assertEqual(finding.title, "AWS")
            self.assertIsNotNone(finding.description)
            self.assertTrue(finding.dynamic_finding)
            self.assertEqual(test.test_type.name, "n0s1 Confluence")
            self.assertEqual(test.description, "Scan from n0s1 Confluence")

    def test_detect_subscanner_returns_correct_type(self):
        with (get_unit_tests_scans_path("n0s1") / "many_findings.json").open(encoding="utf-8") as testfile:
            parser = N0s1Parser()
            data = json.load(testfile)
            subscanner = parser.detect_subscanner(data)
            self.assertEqual("n0s1 Confluence", subscanner)
