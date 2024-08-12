from dojo.models import Test
from dojo.tools.kubescape.parser import KubescapeParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_path


class TestKubescapeParser(DojoTestCase):
    def test_parse_file_has_many_findings(self):
        with open(get_unit_tests_path() + "/scans/kubescape/many_findings.json") as testfile:
            parser = KubescapeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(710, len(findings))

    def test_parse_file_has_many_results(self):
        with open(get_unit_tests_path() + "/scans/kubescape/results.json") as testfile:
            parser = KubescapeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_a_failure(self):
        with open(get_unit_tests_path() + "/scans/kubescape/with_a_failure.json") as testfile:
            parser = KubescapeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
