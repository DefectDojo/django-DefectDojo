import os.path

from ..dojo_test_case import DojoTestCase, get_unit_tests_path
from dojo.tools.awssecurityhub.parser import AwsSecurityHubParser
from dojo.models import Test


def sample_path(file_name):
    return os.path.join("/scans/awssecurityhub", file_name)


class TestAwsSecurityHubParser(DojoTestCase):

    def test_one_finding(self):
        with open(get_unit_tests_path() + sample_path("one_finding.json")) as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(1, len(findings))

    def test_many_findings(self):
        with open(get_unit_tests_path() + sample_path("many_findings.json")) as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(3, len(findings))

    def test_repeated_findings(self):
        with open(get_unit_tests_path() + sample_path("repeated_findings.json")) as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(1, len(findings))

    def test_unique_id(self):
        with open(get_unit_tests_path() + sample_path("one_finding.json")) as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual("arn:aws:securityhub:us-east-1:012345678912:subscription/aws-foundational-security-best-practices/v/1.0.0/IAM.5/finding/de861909-2d26-4e45-bd86-19d2ab6ceef1",
                findings[0].unique_id_from_tool)
