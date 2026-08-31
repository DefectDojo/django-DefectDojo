from dojo.models import Test
from dojo.tools.tflint.parser import TFLintParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestTFLintParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("tflint") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = TFLintParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("tflint") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = TFLintParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual(
                'aws_instance_invalid_type: "t1.2xlarge" is an invalid value as instance_type',
                finding.title,
            )
            self.assertEqual("High", finding.severity)
            self.assertEqual("aws_instance_invalid_type", finding.vuln_id_from_tool)
            self.assertEqual("main.tf", finding.file_path)
            self.assertEqual(8, finding.line)
            self.assertIn("**Location:** main.tf:8", finding.description)
            # This plugin rule ships no documentation link; the field must stay empty
            # rather than carrying an empty string.
            self.assertIsNone(finding.references)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("tflint") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = TFLintParser().get_findings(testfile, Test())
            self.assertEqual(5, len(findings))

            with self.subTest("error maps to High, warning to Medium"):
                self.assertEqual(1, len([f for f in findings if f.severity == "High"]))
                self.assertEqual(4, len([f for f in findings if f.severity == "Medium"]))

            with self.subTest("core ruleset findings keep their documentation link"):
                unused = next(f for f in findings if f.vuln_id_from_tool == "terraform_unused_declarations")
                self.assertEqual("Medium", unused.severity)
                self.assertIn("tflint-ruleset-terraform", unused.references)

            with self.subTest("every finding is anchored in a file"):
                for finding in findings:
                    self.assertEqual("main.tf", finding.file_path)
                    self.assertIsNotNone(finding.line)
