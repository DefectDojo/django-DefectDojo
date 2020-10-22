from django.test import TestCase
from dojo.tools.fortify.parser import FortifyXMLParser
from dojo.models import Test


class TestFortifyParser(TestCase):

    def test_fortify_many_findings(self):
        testfile = "dojo/unittests/scans/fortify/fortify_many_findings.xml"
        parser = FortifyXMLParser(testfile, Test())
        self.assertEqual(324, len(parser.items))

    def test_fortify_few_findings(self):
        testfile = "dojo/unittests/scans/fortify/fortify_few_findings.xml"
        parser = FortifyXMLParser(testfile, Test())
        self.assertEqual(2, len(parser.items))

    def test_fortify_few_findings_count_chart(self):
        testfile = "dojo/unittests/scans/fortify/fortify_few_findings_count_chart.xml"
        parser = FortifyXMLParser(testfile, Test())
        self.assertEqual(3, len(parser.items))
