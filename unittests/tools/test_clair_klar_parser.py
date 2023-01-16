from ..dojo_test_case import DojoTestCase
from dojo.tools.clair_klar.parser import ClairKlarParser


class TestFile(object):
    def read(self):
        return self.content

    def __init__(self, name, content):
        self.name = name
        self.content = content


class TestClairKlarParser(DojoTestCase):

    def test_parse_no_content_no_findings(self):
        my_file_handle = open("unittests/scans/clair_klar/empty.json")
        parser = ClairKlarParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(0, len(findings))

    def test_high_findings(self):
        my_file_handle = open("unittests/scans/clair_klar/high.json")
        parser = ClairKlarParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(6, len(findings))

    def test_mixed_findings(self):
        my_file_handle = open("unittests/scans/clair_klar/mixed.json")
        parser = ClairKlarParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(6, len(findings))
