import os.path

from ..dojo_test_case import DojoTestCase, get_unit_tests_path
from dojo.tools.trufflehog.parser import TruffleHogParser
from dojo.models import Test


def sample_path(file_name):
    return os.path.join(get_unit_tests_path() + "/scans/trufflehog", file_name)


class TestTruffleHogParser(DojoTestCase):

    def test_many_vulns(self):
        test_file = open(sample_path("many_vulns.json"))
        parser = TruffleHogParser()
        findings = parser.get_findings(test_file, Test())
        self.assertEqual(len(findings), 18)
        finding = findings[0]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual(798, finding.cwe)
        self.assertEqual('test_all.py', finding.file_path)
