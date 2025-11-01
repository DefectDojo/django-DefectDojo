
from dojo.models import Test
from dojo.tools.n0s1.parser import N0s1Parser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestN0s1Parser(DojoTestCase):

    def test_n0s1_parser_with_multiple_findings(self):
        with (get_unit_tests_scans_path("n0s1") / "many_findings.json").open(encoding="utf-8") as testfile:
            parser = N0s1Parser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(17, len(findings))
            finding = findings[0]
            self.assertEqual(finding.title, "AWS")
            self.assertIsNotNone(finding.description)
            self.assertTrue(finding.dynamic_finding)

    def test_n0s1_get_tests_returns_correct_subscanner(self):
        with (get_unit_tests_scans_path("n0s1") / "many_findings.json").open(encoding="utf-8") as testfile:
            parser = N0s1Parser()
            tests = parser.get_tests("n0s1 Scanner", testfile)
            self.assertEqual(1, len(tests))
            test = tests[0]
            self.assertEqual("n0s1 Confluence", test.name)
            self.assertEqual("n0s1 Confluence", test.parser_type)
            self.assertEqual("Scan from n0s1 Confluence", test.description)
            self.assertEqual(17, len(test.findings))
            self.assertTrue(all(f.dynamic_finding for f in test.findings))
