import os.path

from django.test import TestCase
from dojo.tools.burp.parser import BurpXmlParser
from dojo.models import Test


def sample_path(file_name):
    return os.path.join('dojo/unittests/scans/burp', file_name)


class TestBurpParser(TestCase):

    def test_burp_without_file_has_no_findings(self):
        parser = BurpXmlParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_burp_with_one_vuln_has_one_finding(self):
        with open(sample_path('one_finding.xml')) as test_file:
            parser = BurpXmlParser(test_file, Test())

        self.assertEqual(1, len(parser.items))

    def test_burp_with_multiple_vulns_has_multiple_findings(self):
        with open(sample_path('seven_findings.xml')) as test_file:
            parser = BurpXmlParser(test_file, Test())

        self.assertEqual(7, len(parser.items))
