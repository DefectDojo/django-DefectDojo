from ..dojo_test_case import DojoTestCase, get_unit_tests_path
from dojo.tools.kubescape.parser import KubescapeParser
from dojo.models import Test


class TestOrtParser(DojoTestCase):
    def test_parse_file_has_many_findings(self):
        testfile = open(
            get_unit_tests_path() + "/scans/kubescape/many_findings.json"
        )
        parser = KubescapeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(710, len(findings))

    def test_parse_file_has_many_results(self):
        testfile = open(
            get_unit_tests_path() + "/scans/kubescape/results.json"
        )
        parser = KubescapeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(20, len(findings))

    def test_parse_file_with_a_failure(self):
        testfile = open(
            get_unit_tests_path() + "/scans/kubescape/with_a_failure.json"
        )
        parser = KubescapeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(18, len(findings))
