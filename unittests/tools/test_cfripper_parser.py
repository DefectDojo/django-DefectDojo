from dojo.models import Test
from dojo.tools.cfripper.parser import CfripperParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestCfripperParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("cfripper") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = CfripperParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("cfripper") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = CfripperParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("PrivilegeEscalationRule: MyPolicy", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("PrivilegeEscalationRule", finding.vuln_id_from_tool)
            self.assertEqual("MyPolicy", finding.component_name)
            self.assertIn("**Resource types:** AWS::IAM::Policy", finding.description)
            self.assertIn("**Rule mode:** BLOCKING", finding.description)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("cfripper") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = CfripperParser().get_findings(testfile, Test())
            self.assertEqual(5, len(findings))

            with self.subTest("CFRipper's risk value is the severity"):
                self.assertEqual(1, len([f for f in findings if f.severity == "High"]))
                self.assertEqual(2, len([f for f in findings if f.severity == "Medium"]))
                self.assertEqual(2, len([f for f in findings if f.severity == "Low"]))

            with self.subTest("findings are attributed to the resource that tripped them"):
                by_rule = {f.vuln_id_from_tool: f for f in findings}
                self.assertEqual("MyBucket", by_rule["S3ObjectVersioningRule"].component_name)
                self.assertEqual("MyPolicy", by_rule["WildcardResourceRule"].component_name)
