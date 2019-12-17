from django.test import TestCase
from dojo.tools.fortify.parser import FortifyXMLParser
from dojo.models import Test
from pathlib import Path


class TestFortifyParser(TestCase):

    def test_fortify_many_findings(self):
        testfile = Path("dojo/unittests/scans/fortify/fortify_many_findings.xml")
        parser = FortifyXMLParser(testfile, Test())
        self.assertEqual(334, len(parser.items))

    def test_fortify_few_findings(self):
        testfile = Path("dojo/unittests/scans/fortify/fortify_few_findings.xml")
        parser = FortifyXMLParser(testfile, Test())
        self.assertEqual(2, len(parser.items))
