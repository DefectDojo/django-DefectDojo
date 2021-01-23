from django.test import TestCase
from dojo.tools.ort.parser import OrtParser
from dojo.models import Test


class TestOrtParser(TestCase):

    def test_parse_without_file_has_no_finding(self):
        with self.assertRaisesRegex(Exception, "Invalid format"):
            parser = OrtParser(None, Test())

    def test_parse_file_has_many_finding_one_tool(self):
        testfile = open("dojo/unittests/scans/ort/evaluated-model-reporter-test-output.json")
        parser = OrtParser(testfile, Test())
        testfile.close()
        self.assertEqual(2, len(parser.items))
