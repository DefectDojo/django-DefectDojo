from django.test import TestCase
from dojo.tools.fortify.parser import FortifyParser
from dojo.models import Test
from datetime import datetime


class TestFortifyParser(TestCase):
    def test_fortify_many_findings(self):
        testfile = "dojo/unittests/scans/fortify/fortify_many_findings.xml"
        parser = FortifyParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(324, len(findings))
        self.assertEqual(datetime(2019, 12, 17), findings[0].date)

    def test_fortify_few_findings(self):
        testfile = "dojo/unittests/scans/fortify/fortify_few_findings.xml"
        parser = FortifyParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(2, len(findings))
        self.assertEqual(datetime(2019, 5, 7), findings[0].date)

    def test_fortify_few_findings_count_chart(self):
        testfile = "dojo/unittests/scans/fortify/fortify_few_findings_count_chart.xml"
        parser = FortifyParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(3, len(findings))
        self.assertEqual(datetime(2019, 5, 7), findings[0].date)
