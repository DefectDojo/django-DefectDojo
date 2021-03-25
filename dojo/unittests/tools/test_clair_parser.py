from django.test import TestCase
from dojo.tools.clair.parser import ClairParser


class TestFile(object):
    def read(self):
        return self.content

    def __init__(self, name, content):
        self.name = name
        self.content = content


class TestClairParser(TestCase):

    def test_no_findings(self):
        my_file_handle = open("dojo/unittests/scans/clair/empty.json")
        parser = ClairParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(0, len(findings))

    def test_many_findings(self):
        my_file_handle = open("dojo/unittests/scans/clair/many_vul.json")
        parser = ClairParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(35, len(findings))
