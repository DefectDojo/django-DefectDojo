from ..dojo_test_case import DojoTestCase, get_unit_tests_path
from dojo.tools.kubescape.parser import KubescapeParser
from dojo.models import Test


class TestOrtParser(DojoTestCase):
    def test_parse_file_has_many_finding_one_tool(self):
        testfile = open(
            get_unit_tests_path() + "/scans/kubescape/many_findings.json"
        )
        parser = KubescapeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(44, len(findings))
