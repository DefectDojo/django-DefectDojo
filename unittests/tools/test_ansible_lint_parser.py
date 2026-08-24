from dojo.models import Test
from dojo.tools.ansible_lint.parser import AnsibleLintParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestAnsibleLintParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("ansible_lint") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = AnsibleLintParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("ansible_lint") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = AnsibleLintParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("name[play]", finding.vuln_id_from_tool)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("playbooks/playbook.yml", finding.file_path)
            self.assertEqual(1, finding.line)
            self.assertIn("All plays should be named.", finding.title)
            self.assertIn("**Categories:** idiom", finding.description)
            self.assertIn("docs.ansible.com", finding.references)
            self.assertTrue(finding.unique_id_from_tool)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("ansible_lint") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = AnsibleLintParser().get_findings(testfile, Test())
            self.assertEqual(16, len(findings))

            with self.subTest("the security-relevant rules are present and categorised"):
                rules = {f.vuln_id_from_tool for f in findings}
                self.assertIn("risky-file-permissions", rules)
                self.assertIn("command-instead-of-shell", rules)
                shell = next(f for f in findings if f.vuln_id_from_tool == "command-instead-of-shell")
                self.assertIn("**Categories:** command-shell", shell.description)

            with self.subTest("every finding is anchored in the playbook"):
                for finding in findings:
                    self.assertEqual("playbooks/playbook.yml", finding.file_path)
                    self.assertIsNotNone(finding.line)

            with self.subTest("fingerprints distinguish repeated rules"):
                permissions = [f for f in findings if f.vuln_id_from_tool == "risky-file-permissions"]
                self.assertEqual(len(permissions), len({f.unique_id_from_tool for f in permissions}))

    def test_severity_scale(self):
        """ansible-lint emits the Code Climate scale, not its own."""
        parser = AnsibleLintParser()
        self.assertEqual("Critical", parser.SEVERITY["blocker"])
        self.assertEqual("High", parser.SEVERITY["critical"])
        self.assertEqual("Medium", parser.SEVERITY["major"])
        self.assertEqual("Low", parser.SEVERITY["minor"])
        self.assertEqual("Info", parser.SEVERITY["info"])

    def test_line_is_read_from_either_position_shape(self):
        parser = AnsibleLintParser()
        self.assertEqual(7, parser._line({"positions": {"begin": {"line": 7, "column": 3}}}))
        self.assertEqual(9, parser._line({"positions": {"begin": 9}}))
        self.assertIsNone(parser._line({}))
