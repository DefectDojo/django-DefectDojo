from dojo.models import Test
from dojo.tools.cloudformation_guard.parser import CloudFormationGuardParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestCloudFormationGuardParser(DojoTestCase):

    def test_parse_no_findings(self):
        """A compliant template reports its rules under compliant, which are not findings."""
        with (get_unit_tests_scans_path("cloudformation_guard") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = CloudFormationGuardParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("cloudformation_guard") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = CloudFormationGuardParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("s3_bucket_encryption_enabled", finding.vuln_id_from_tool)
            self.assertEqual("template.yaml", finding.file_path)
            self.assertEqual("/Resources/DataBucket/Properties", finding.component_name)
            self.assertEqual("Medium", finding.severity)

            with self.subTest("the rule's own violation message is kept"):
                self.assertIn("S3 buckets must define BucketEncryption.", finding.description)

            with self.subTest("a unary check records the property that was missing"):
                self.assertIn("**Check type:** Unary", finding.description)
                self.assertIn("**Missing property:** BucketEncryption", finding.description)
                self.assertIn("**Property resolution:** UnResolved", finding.description)

            with self.subTest("the template line is recovered from cfn-guard's message"):
                self.assertEqual(4, finding.line)

    def test_parse_many_findings(self):
        """Unary and Binary clauses nest differently, and both must be understood."""
        with (get_unit_tests_scans_path("cloudformation_guard") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = CloudFormationGuardParser().get_findings(testfile, Test())
            self.assertEqual(2, len(findings))

            by_rule = {f.vuln_id_from_tool: f for f in findings}
            self.assertEqual(
                {"s3_bucket_encryption_enabled", "security_group_no_open_ssh"},
                set(by_rule),
            )

            with self.subTest("the binary clause resolves its path and line too"):
                binary = by_rule["security_group_no_open_ssh"]
                self.assertIn("**Check type:** Binary", binary.description)
                self.assertEqual(
                    "/Resources/OpenGroup/Properties/SecurityGroupIngress/0/CidrIp",
                    binary.component_name,
                )
                self.assertEqual(13, binary.line)

            with self.subTest("the offending value is recorded, not just the rule name"):
                self.assertIn("0.0.0.0/0", by_rule["security_group_no_open_ssh"].description)

            with self.subTest("every finding is attributed to the template"):
                for finding in findings:
                    self.assertEqual("template.yaml", finding.file_path)
                    self.assertTrue(finding.static_finding)
                    self.assertFalse(finding.dynamic_finding)

    def test_position_is_not_taken_from_the_rule_file_literal(self):
        """
        A binary check names two positions and the second is a literal from the rules file.

        cfn-guard reports that literal at [L:0,C:0]; picking it would put every finding on line
        zero of the template.
        """
        parser = CloudFormationGuardParser()
        line = parser._line_from_messages(
            'Check was not compliant as property value [Path=/Resources/G/Properties/CidrIp[L:13,C:18] '
            'Value="0.0.0.0/0"] equal to value [Path=[L:0,C:0] Value="0.0.0.0/0"].',
            None,
            "/Resources/G/Properties/CidrIp",
        )
        self.assertEqual(13, line)

    def test_a_failing_rule_with_no_clause_detail_is_still_imported(self):
        parser = CloudFormationGuardParser()
        findings = parser._rule_findings({"name": "some_rule", "checks": []}, "template.yaml", Test())
        self.assertEqual(1, len(findings))
        self.assertEqual("some_rule", findings[0].title)
        self.assertEqual("template.yaml", findings[0].file_path)
