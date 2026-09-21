from dojo.models import Test
from dojo.tools.two_ms.parser import TwoMsParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestTwoMsParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("two_ms") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = TwoMsParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("two_ms") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = TwoMsParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Secret detected: Jwt", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("37dfe666-1961-48f8-b618-fa6321c216d1", finding.vuln_id_from_tool)
            self.assertEqual("testData/secrets/jwt.txt", finding.file_path)
            self.assertEqual(8.2, finding.cvssv3_score)
            self.assertIn("**Validation status:** Unknown", finding.description)
            self.assertIn("Revoke and rotate", finding.mitigation)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_parse_many_findings(self):
        """2ms groups results by secret id, so every row across every group is a Finding."""
        with (get_unit_tests_scans_path("two_ms") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = TwoMsParser().get_findings(testfile, Test())
            self.assertEqual(9, len(findings))

            with self.subTest("severities come from the report, not a default"):
                self.assertEqual(3, len([f for f in findings if f.severity == "High"]))
                self.assertEqual(6, len([f for f in findings if f.severity == "Low"]))

            with self.subTest("every row in one file survives as its own Finding"):
                # jwt.txt holds two distinct secrets, one of which 2ms found on two lines.
                # That is three rows: two share a line number, two share a group id, and
                # no two share both.
                jwt = [f for f in findings if f.file_path == "testData/secrets/jwt.txt"]
                self.assertEqual(3, len(jwt))
                self.assertEqual([0, 0, 1], sorted(f.line for f in jwt))
                for finding in jwt:
                    self.assertIsNone(finding.unique_id_from_tool)

            with self.subTest("two secrets on the same line stay distinguishable"):
                # The default hashcode fields include description precisely because
                # title + file_path + line does not separate these two.
                same_line = [
                    f for f in findings
                    if f.file_path == "testData/secrets/jwt.txt" and f.line == 0
                ]
                self.assertEqual(2, len(same_line))
                self.assertNotEqual(same_line[0].description, same_line[1].description)

            with self.subTest("rule names reach the title"):
                titles = {f.title for f in findings}
                self.assertIn("Secret detected: Github-Pat-Custom", titles)
                self.assertIn("Secret detected: Mock-Custom-Rule", titles)

            with self.subTest("cvss scores are carried across"):
                self.assertEqual({1, 7, 8.2}, {f.cvssv3_score for f in findings})
