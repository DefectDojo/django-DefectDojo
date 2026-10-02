from dojo.models import Test
from dojo.tools.dockerfile_lint.parser import DockerfileLintParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDockerfileLintParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("dockerfile_lint") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = DockerfileLintParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("dockerfile_lint") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = DockerfileLintParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("is_latest_tag: base image uses 'latest' tag", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("is_latest_tag", finding.vuln_id_from_tool)
            self.assertEqual(1, finding.line)
            self.assertIn("**Line content:** `FROM ubuntu:latest`", finding.description)
            self.assertIn("unpredictable builds", finding.description)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("dockerfile_lint") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = DockerfileLintParser().get_findings(testfile, Test())
            self.assertEqual(4, len(findings))

            with self.subTest("the buckets are the severity scale"):
                self.assertEqual(3, len([f for f in findings if f.severity == "High"]))
                self.assertEqual(1, len([f for f in findings if f.severity == "Low"]))

            with self.subTest("file-level rules carry no line number"):
                # Two of the errors are missing LABELs, which apply to the whole file and
                # which dockerfile_lint reports as line -1.
                fileless = [f for f in findings if f.line is None]
                self.assertEqual(2, len(fileless))
                for finding in fileless:
                    self.assertIn("Required LABEL", finding.title)

            with self.subTest("an unlabelled rule still gets a title from its message"):
                unlabelled = [f for f in findings if f.vuln_id_from_tool is None]
                self.assertEqual(2, len(unlabelled))
                for finding in unlabelled:
                    self.assertTrue(finding.title)
