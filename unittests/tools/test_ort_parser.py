from ..dojo_test_case import DojoParserTestCase, get_unit_tests_path
from dojo.tools.ort.parser import OrtParser
from dojo.models import Test


class TestOrtParser(DojoParserTestCase):

    parser = OrtParser()

    def test_parse_without_file_has_no_finding(self):
        findings = self.parser.get_findings(None, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_has_many_finding_one_tool(self):
        testfile = open(
            get_unit_tests_path() + "/scans/ort/evaluated-model-reporter-test-output.json"
        )
        findings = self.parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(2, len(findings))
