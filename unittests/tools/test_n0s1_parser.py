
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
