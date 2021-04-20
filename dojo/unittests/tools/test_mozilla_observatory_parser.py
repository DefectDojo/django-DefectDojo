from os import path

from django.test import TestCase
from dojo.models import Test
from dojo.tools.mozilla_observatory.parser import MozillaObservatoryParser


class TestMozillaObservatoryParser(TestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):

        testfile = open(path.join(path.dirname(__file__), "scans/mozilla_observatory/mozilla_no_vuln.json"))
        parser = MozillaObservatoryParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_two_vuln_has_two_findings(self):
        testfile = open(
            path.join(path.dirname(__file__), "scans/mozilla_observatory/mozilla_gitlab_two_vuln.json")
        )
        parser = MozillaObservatoryParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(2, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        testfile = open(
            path.join(path.dirname(__file__), "scans/mozilla_observatory/mozilla_google_many_vuln.json")
        )
        parser = MozillaObservatoryParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(6, len(findings))
