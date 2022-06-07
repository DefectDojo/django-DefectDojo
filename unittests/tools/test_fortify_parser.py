from ..dojo_test_case import DojoTestCase, get_unit_tests_path
from dojo.tools.fortify.parser import FortifyParser
from dojo.models import Test
from datetime import datetime


class TestFortifyParser(DojoTestCase):
    def test_fortify_many_findings(self):
        testfile = get_unit_tests_path() + "/scans/fortify/fortify_many_findings.xml"
        parser = FortifyParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(324, len(findings))
        self.assertEqual(datetime(2019, 12, 17), findings[0].date)

    def test_fortify_few_findings(self):
        testfile = get_unit_tests_path() + "/scans/fortify/fortify_few_findings.xml"
        parser = FortifyParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(2, len(findings))
        self.assertEqual(datetime(2019, 5, 7), findings[0].date)

    def test_fortify_few_findings_count_chart(self):
        testfile = get_unit_tests_path() + "/scans/fortify/fortify_few_findings_count_chart.xml"
        parser = FortifyParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(3, len(findings))
        self.assertEqual(datetime(2019, 5, 7), findings[0].date)
