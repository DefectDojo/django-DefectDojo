from os import path

from django.test import TestCase
from dojo.tools.clair_klar.parser import ClairKlarParser


class TestClairKlarParser(TestCase):

    def test_parse_no_content_no_findings(self):
        my_file_handle = open(path.join(path.dirname(__file__), "scans/clair-klar/empty.json"))
        parser = ClairKlarParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(0, len(findings))

    def test_high_findings(self):
        my_file_handle = open(path.join(path.dirname(__file__), "scans/clair-klar/high.json"))
        parser = ClairKlarParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(6, len(findings))

    def test_mixed_findings(self):
        my_file_handle = open(path.join(path.dirname(__file__), "scans/clair-klar/mixed.json"))
        parser = ClairKlarParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(6, len(findings))
