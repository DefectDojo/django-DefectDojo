import os.path

from django.test import TestCase
from dojo.tools.trufflehog.parser import TruffleHogParser
from dojo.models import Test


def sample_path(file_name):
    return os.path.join("dojo/unittests/scans/trufflehog", file_name)


class TestTruffleHogParser(TestCase):

    def test_many_vulns(self):
        test_file = open(sample_path("many_vulns.json"))
        parser = TruffleHogParser()
        findings = parser.get_findings(test_file, Test())
        self.assertEqual(len(findings), 18)
        finding = findings[0]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual(798, finding.cwe)
        self.assertEqual('test_all.py', finding.file_path)
