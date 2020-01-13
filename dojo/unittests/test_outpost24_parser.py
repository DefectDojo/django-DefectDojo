from django.test import TestCase
from dojo.tools.outpost24.parser import Outpost24Parser
from dojo.models import Test


class TestOutpost24Parser(TestCase):

    def assert_file_has_n_items(self, filename, item_count):
        with open(filename) as file:
            parser = Outpost24Parser(file, Test())
        self.assertEquals(item_count, len(parser.items))
        if item_count > 0:
            for item in parser.items:
                self.assertEquals(1, len(item.unsaved_endpoints), msg='Finding should have one endpoint')

    def test_parser_no_items(self):
        self.assert_file_has_n_items('dojo/unittests/scans/outpost24/none.xml', 0)

    def test_parser_one_item(self):
        self.assert_file_has_n_items('dojo/unittests/scans/outpost24/one.xml', 1)

    def test_parser_sample_items(self):
        self.assert_file_has_n_items('dojo/unittests/scans/outpost24/sample.xml', 24)
