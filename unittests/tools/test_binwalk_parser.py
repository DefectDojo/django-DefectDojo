from dojo.models import Test
from dojo.tools.binwalk.parser import BinwalkParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestBinwalkParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("binwalk") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = BinwalkParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("binwalk") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = BinwalkParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("copyright signature at offset 4716889", finding.title)
            self.assertEqual("copyright", finding.vuln_id_from_tool)
            self.assertEqual("firmware/example.bin", finding.file_path)
            self.assertIn("**Offset:** 4716889", finding.description)
            self.assertIn("**Confidence:**", finding.description)
            self.assertTrue(finding.unique_id_from_tool)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_everything_binwalk_reports_is_informational(self):
        """Binwalk identifies what a file contains; it does not judge it."""
        with (get_unit_tests_scans_path("binwalk") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = BinwalkParser().get_findings(testfile, Test())
            self.assertEqual(4, len(findings))
            self.assertEqual({"Info"}, {f.severity for f in findings})

            with self.subTest("distinct signature classes are preserved"):
                self.assertEqual(
                    {"copyright", "gzip", "sha256", "aes_sbox"},
                    {f.vuln_id_from_tool for f in findings},
                )

            with self.subTest("every match carries its own id and the same source file"):
                self.assertEqual(4, len({f.unique_id_from_tool for f in findings}))
                for finding in findings:
                    self.assertEqual("firmware/example.bin", finding.file_path)
