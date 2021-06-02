import os.path

from django.test import TestCase
from dojo.tools.awssecurityhub.parser import AwsSecurityHubParser
from dojo.models import Test


def sample_path(file_name):
    return os.path.join("dojo/unittests/scans/awssecurityhub", file_name)


class TestAwsSecurityHubParser(TestCase):

    def test_one_finding(self):
        with open(sample_path("one_finding.json")) as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(1, len(findings))

    def test_many_findings(self):
        with open(sample_path("many_findings.json")) as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(3, len(findings))

    def test_repeated_findings(self):
        with open(sample_path("repeated_findings.json")) as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(1, len(findings))

    def test_unique_id(self):
        with open(sample_path("one_finding.json")) as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual("de861909-2d26-4e45-bd86-19d2ab6ceef1",
                findings[0].unique_id_from_tool)
