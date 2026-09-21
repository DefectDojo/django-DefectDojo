from dojo.models import Test
from dojo.tools.dodgy.parser import DodgyParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDodgyParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("dodgy") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = DodgyParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("dodgy") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = DodgyParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Amazon Web Services secret key", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("aws_secret_key", finding.vuln_id_from_tool)
            self.assertEqual("src/sec_test.py", finding.file_path)
            self.assertEqual(2, finding.line)
            self.assertIn("**Location:** src/sec_test.py:2", finding.description)
            self.assertIn("rotate it", finding.mitigation)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_a_hardcoded_secret_is_always_high(self):
        with (get_unit_tests_scans_path("dodgy") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = DodgyParser().get_findings(testfile, Test())
            self.assertEqual(4, len(findings))
            self.assertEqual({"High"}, {f.severity for f in findings})

            with self.subTest("both rule types survive"):
                self.assertEqual({"aws_secret_key", "secret"}, {f.vuln_id_from_tool for f in findings})

            with self.subTest("the same secret in two files stays two findings"):
                aws = [f for f in findings if f.vuln_id_from_tool == "aws_secret_key"]
                self.assertEqual(2, len(aws))
                self.assertEqual({"src/sec_test.py", "src/secrets2.py"}, {f.file_path for f in aws})
