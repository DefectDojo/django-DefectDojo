from django.test import TestCase
from dojo.tools.outpost24.parser import Outpost24Parser
from dojo.models import Test


class TestOutpost24Parser(TestCase):

    def test_parser_sample_items(self):
        with open('dojo/unittests/scans/outpost24/sample.xml') as sample:
            parser = Outpost24Parser(sample, Test())
        self.assertEquals(24, len(parser.items))
