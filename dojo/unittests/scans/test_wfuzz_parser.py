from django.test import TestCase
from dojo.tools.wfuzz.parser import wfuzzJSONParser
from dojo.models import Test


class TestwfuzzJSONParser(TestCase):

    def test_parse_without_file_has_no_finding(self):
        parser = wfuzzJSONParser(None, Test())
        self.assertEqual(0, len(parser.items))