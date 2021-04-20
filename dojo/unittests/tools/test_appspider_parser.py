from os import path

from django.test import TestCase
from dojo.models import Engagement, Finding, Product, Test
from dojo.tools.appspider.parser import AppSpiderParser


class TestAppSpiderParser(TestCase):

    def test_appspider_parser_has_one_finding(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        testfile = open(path.join(path.dirname(__file__), "scans/appspider/one_vuln.xml"))
        parser = AppSpiderParser()
        findings = parser.get_findings(testfile, test)
        testfile.close()
        self.assertEqual(1, len(findings))
        item = findings[0]
        with self.subTest(item=0):
            self.assertEqual(525, item.cwe)

    def convert_severity(self):
        with self.subTest(val="0-Safe"):
            self.assertIn(
                Finding.SEVERITIES, AppSpiderParser.convert_severity("0-Safe")
            )
