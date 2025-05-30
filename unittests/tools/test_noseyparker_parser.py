from dojo.models import Test
from dojo.tools.noseyparker.parser import NoseyParkerParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestNoseyParkerParser(DojoTestCase):

    def test_noseyparker_parser__no_vulns(self):
        with (get_unit_tests_scans_path("noseyparker") / "noseyparker_zero_vul.jsonl").open(encoding="utf-8") as testfile:
            parser = NoseyParkerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_noseyparker_parser_one_vuln(self):
        with (get_unit_tests_scans_path("noseyparker") / "noseyparker_one_vul.jsonl").open(encoding="utf-8") as testfile:
            parser = NoseyParkerParser()
            findings = parser.get_findings(testfile, Test())
            finding = findings[0]
            self.assertEqual("app/schema/config.py", finding.file_path)
            self.assertEqual("High", finding.severity)
            self.assertEqual(798, finding.cwe)
            self.assertEqual(1, len(findings))

    def test_noseyparker_parser_many_vulns(self):
        # Testfile contains 5 lines (Middle 2 are duplicates and line #4 has 2 of the same exact matches)
        with (get_unit_tests_scans_path("noseyparker") / "noseyparker_many_vul.jsonl").open(encoding="utf-8") as testfile:
            parser = NoseyParkerParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                self.assertEqual("High", finding.severity)
                self.assertEqual(798, finding.cwe)
            self.assertEqual(3, len(findings))

    def test_noseyparker_parser_error(self):
        with self.assertRaises(ValueError) as context, \
          (get_unit_tests_scans_path("noseyparker") / "empty_with_error.json").open(encoding="utf-8") as testfile:
            parser = NoseyParkerParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.assertEqual(0, len(findings))
            self.assertIn(
                "Invalid Nosey Parker data, make sure to use Nosey Parker v0.16.0", str(context.exception),
            )
            self.assertIn("ECONNREFUSED", str(context.exception))

    def test_noseyparker_version_0_22_0(self):
        with (get_unit_tests_scans_path("noseyparker") / "noseyparker_0_22_0.jsonl").open(encoding="utf-8") as testfile:
            parser = NoseyParkerParser()
            findings = parser.get_findings(testfile, Test())
            finding = findings[0]
            self.assertEqual("High", finding.severity)
            self.assertEqual(798, finding.cwe)
            self.assertEqual(33, len(findings))
            finding = findings[10]
            self.assertEqual("High", finding.severity)

    def test_noseyparker_version_0_22_0_without_githistory(self):
        with (get_unit_tests_scans_path("noseyparker") / "noseyparker_0_22_0_without_githistory.jsonl").open(encoding="utf-8") as testfile:
            parser = NoseyParkerParser()
            findings = parser.get_findings(testfile, Test())
            finding = findings[0]
            self.assertEqual("High", finding.severity)
            self.assertEqual(798, finding.cwe)
            self.assertEqual(6, len(findings))
