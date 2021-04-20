from os import path

from django.test import TestCase
from dojo.models import Test
from dojo.tools.awssecurityhub.parser import AwsSecurityHubParser


class TestAwsSecurityHubParser(TestCase):

    def test_one_finding(self):
        with open(path.join(path.dirname(__file__), "scans/awssecurityhub/one_finding.json")) as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(1, len(findings))

    def test_many_findings(self):
        with open(path.join(path.dirname(__file__), "scans/awssecurityhub/many_findings.json")) as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(3, len(findings))

    def test_repeated_findings(self):
        with open(path.join(path.dirname(__file__), "scans/awssecurityhub/repeated_findings.json")) as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(1, len(findings))
