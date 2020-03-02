from django.test import TestCase
from dojo.tools.dsop.parser import DsopParser

from dojo.models import Test


class TestDsopParser(TestCase):

    def test_zero_findings(self):
        with (open('dojo/unittests/scans/dsop/zero_vuln.xlsx', 'rb')) as file:
            parser = DsopParser(file, Test())
        self.assertEquals(len(parser.items), 0)

    def test_many_findings(self):
        with open('dojo/unittests/scans/dsop/many_vuln.xlsx', 'rb') as file:
            parser = DsopParser(file, Test())
        self.assertEquals(len(parser.items), 4984)
