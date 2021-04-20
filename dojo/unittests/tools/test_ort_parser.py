from os import path

from django.test import TestCase
from dojo.models import Test
from dojo.tools.ort.parser import OrtParser


class TestOrtParser(TestCase):
    def test_parse_without_file_has_no_finding(self):
        parser = OrtParser()
        findings = parser.get_findings(None, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_has_many_finding_one_tool(self):
        testfile = open(
            path.join(path.dirname(__file__), "scans/ort/evaluated-model-reporter-test-output.json")
        )
        parser = OrtParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(2, len(findings))
