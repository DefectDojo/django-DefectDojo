from dojo.models import Test
from dojo.tools.kingfisher.parser import KingfisherParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestKingfisherParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("kingfisher") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = KingfisherParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        """A credential Kingfisher validated as live is Critical regardless of confidence."""
        with (get_unit_tests_scans_path("kingfisher") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = KingfisherParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Critical", finding.severity)
            self.assertEqual("kingfisher.aws.2", finding.vuln_id_from_tool)
            self.assertEqual("17034522315778178539", finding.unique_id_from_tool)
            self.assertEqual(1, finding.line)
            # The trailing space Kingfisher emits on this path must not reach the Finding.
            self.assertEqual("/tmp/repo/tmp/secretstuff/utf8.txt", finding.file_path)
            self.assertIn("**Validation:** Active Credential", finding.description)
            self.assertIn("Revoke and rotate", finding.mitigation)
            self.assertTrue(finding.static_finding)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("kingfisher") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = KingfisherParser().get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

            with self.subTest("an inactive credential falls back to match confidence"):
                inactive = [f for f in findings if f.severity == "Medium"]
                self.assertEqual(2, len(inactive))
                for finding in inactive:
                    self.assertEqual("kingfisher.alibabacloud.2", finding.vuln_id_from_tool)
                    self.assertIn("**Validation:** Inactive Credential", finding.description)
                    self.assertIn("**Confidence:** medium", finding.description)

            with self.subTest("only the live credential is Critical"):
                self.assertEqual(1, len([f for f in findings if f.severity == "Critical"]))

            with self.subTest("each match carries its own fingerprint"):
                fingerprints = {f.unique_id_from_tool for f in findings}
                self.assertEqual(3, len(fingerprints))

            with self.subTest("titles come from the rule name"):
                self.assertIn("Alibaba Access Key Secret", [f.title for f in findings])
