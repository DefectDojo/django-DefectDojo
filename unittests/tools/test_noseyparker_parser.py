from django.test import TestCase

from dojo.models import Test
from dojo.tools.noseyparker.parser import NoseyParkerParser


class TestNoseyParkerParser(TestCase):

    def test_noseyparker_parser__no_vulns(self):
        with open("unittests/scans/noseyparker/noseyparker_zero_vul.jsonl") as testfile:
            parser = NoseyParkerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_noseyparker_parser_one_vuln(self):
        with open("unittests/scans/noseyparker/noseyparker_one_vul.jsonl") as testfile:
            parser = NoseyParkerParser()
            findings = parser.get_findings(testfile, Test())
            finding = findings[0]
            self.assertEqual("app/schema/config.py", finding.file_path)
            self.assertEqual("High", finding.severity)
            self.assertEqual(798, finding.cwe)
            self.assertEqual(1, len(findings))

    def test_noseyparker_parser_many_vulns(self):
        # Testfile contains 5 lines (Middle 2 are duplicates and line #4 has 2 of the same exact matches)
        with open("unittests/scans/noseyparker/noseyparker_many_vul.jsonl") as testfile:
            parser = NoseyParkerParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                self.assertEqual("High", finding.severity)
                self.assertEqual(798, finding.cwe)
            self.assertEqual(3, len(findings))

    def test_noseyparker_parser_error(self):
        with self.assertRaises(ValueError) as context:
            with open("unittests/scans/noseyparker/empty_with_error.json") as testfile:
                parser = NoseyParkerParser()
                findings = parser.get_findings(testfile, Test())
                testfile.close()
                self.assertEqual(0, len(findings))
                self.assertTrue(
                    "Invalid Nosey Parker data, make sure to use Nosey Parker v0.16.0" in str(context.exception),
                )
                self.assertTrue("ECONNREFUSED" in str(context.exception))
