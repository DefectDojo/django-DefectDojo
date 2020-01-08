from django.test import TestCase
from dojo.tools.outpost24.parser import Outpost24Parser
from dojo.models import Test


class TestOutpost24Parser(TestCase):

    def test_parser_no_items(self):
        parser = Outpost24Parser(None, Test())
        self.assertEquals(0, len(parser.items))

    def test_parser_sample_items(self):
        with open('dojo/unittests/scans/outpost24/sample.xml') as sample:
            parser = Outpost24Parser(sample, Test())
        self.assertEquals(47, len(parser.items))
