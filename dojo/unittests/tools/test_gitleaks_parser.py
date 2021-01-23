from django.test import TestCase
from dojo.tools.gitleaks.parser import GitleaksJSONParser
from dojo.models import Test


class TestGitleaksParser(TestCase):

    def test_parse_without_file_has_no_finding(self):
        parser = GitleaksJSONParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_one_finding(self):
        testfile = open("dojo/unittests/scans/gitleaks/data_one.json")
        parser = GitleaksJSONParser(testfile, Test())
        self.assertEqual(1, len(parser.items))

    def test_parse_file_with_multiple_finding(self):
        testfile = open("dojo/unittests/scans/gitleaks/data_many.json")
        parser = GitleaksJSONParser(testfile, Test())
        self.assertEqual(2, len(parser.items))
