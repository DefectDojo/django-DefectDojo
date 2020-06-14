from django.test import TestCase
from dojo.tools.eslint.parser import ESLintParser
from dojo.models import Test


class TestBrakemanScanParser(TestCase):
    def test_parse_file_has_two_findings(self):
        testfile = open("dojo/unittests/scans/eslint/scan.json")
        parser = ESLintParser(testfile, Test())
        testfile.close()
        self.assertEqual(2, len(parser.items))

