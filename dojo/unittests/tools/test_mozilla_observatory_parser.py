from django.test import TestCase
from dojo.tools.mozilla_observatory.parser import MozillaObservatoryJSONParser
from dojo.models import Test


class TestMozillaObservatoryJSONParser(TestCase):

    def test_parse_without_file_has_no_findings(self):
        parser = MozillaObservatoryJSONParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_no_vuln_has_no_findings(self):

        testfile = open("dojo/unittests/scans/mozilla_observatory/mozilla_no_vuln.json")
        parser = MozillaObservatoryJSONParser(testfile, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_two_vuln_has_two_findings(self):
        testfile = open("dojo/unittests/scans/mozilla_observatory/mozilla_gitlab_two_vuln.json")
        parser = MozillaObservatoryJSONParser(testfile, Test())
        self.assertEqual(2, len(parser.items))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        testfile = open("dojo/unittests/scans/mozilla_observatory/mozilla_google_many_vuln.json")
        parser = MozillaObservatoryJSONParser(testfile, Test())
        self.assertEqual(6, len(parser.items))
