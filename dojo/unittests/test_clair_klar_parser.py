from django.test import TestCase
from dojo.tools.clair_klar.parser import ClairKlarParser


class TestFile(object):

    def read(self):
        return self.content

    def __init__(self, name, content):
        self.name = name
        self.content = content


class TestClairKlarParser(TestCase):

    def test_parse_no_structure_exception(self):
        with self.assertRaises(Exception):
            ClairKlarParser(None, None)

    def test_parse_no_content_no_findings(self):
        my_file_handle = open("dojo/unittests/scans/clair-klar/empty.json")
        self.parser = ClairKlarParser(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(0, len(self.parser.items))

    def test_high_findings(self):
        my_file_handle = open("dojo/unittests/scans/clair-klar/high.json")
        self.parser = ClairKlarParser(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(6, len(self.parser.items))

    def test_mixed_findings(self):
        my_file_handle = open("dojo/unittests/scans/clair-klar/mixed.json")
        self.parser = ClairKlarParser(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(6, len(self.parser.items))
