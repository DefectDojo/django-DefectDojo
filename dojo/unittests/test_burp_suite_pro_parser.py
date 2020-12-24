from django.test import TestCase

from dojo.models import Test
from dojo.tools.burp_suite_pro.parser import BurpSuiteProParser


class TestParser(TestCase):
    def test_example_report(self):
        testfile = 'dojo/unittests/scans/burp_suite_pro/example.json'
        test = Test()
        with open(testfile) as f:
            test_parser = BurpSuiteProParser(f, test)
        self.assertIsNotNone(test.title)
        self.assertEqual(5, len(test_parser.items))
        item = parser.items[0]
        self.assertEqual('Info', item.severity)
        self.assertEqual('TLS cookie without secure flag set', item.title)
        self.assertEqual('5605602767570803712', item.unique_id_from_tool)
        self.assassertEqual('5243392', item.vuln_id_from_tool)
