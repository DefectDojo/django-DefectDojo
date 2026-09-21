from dojo.models import Test
from dojo.tools.grant.parser import GrantParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestGrantParser(DojoTestCase):

    def test_parse_no_findings(self):
        """A report with only allowed packages produces nothing."""
        with (get_unit_tests_scans_path("grant") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = GrantParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        """The allowed package is filtered out; only the denied one is a finding."""
        with (get_unit_tests_scans_path("grant") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = GrantParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("itsdangerous 2.2.0: no license, denied by policy", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("itsdangerous", finding.component_name)
            self.assertEqual("2.2.0", finding.component_version)
            self.assertEqual("UNLICENSED", finding.vuln_id_from_tool)
            self.assertIn("denied by policy", finding.description)
            self.assertIn("allow-list", finding.mitigation)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("grant") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = GrantParser().get_findings(testfile, Test())
            # 14 denied packages plus one allowed that must not appear.
            self.assertEqual(14, len(findings))
            self.assertEqual({"High"}, {f.severity for f in findings})

            with self.subTest("the allowed package is not among the findings"):
                self.assertNotIn("example-permissive", {f.component_name for f in findings})

            with self.subTest("each denied package is inventoried with a version"):
                for finding in findings:
                    self.assertTrue(finding.component_name)
                    self.assertTrue(finding.component_version)
