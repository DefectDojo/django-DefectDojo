from django.test import TestCase

from dojo.models import Test, Product, Engagement
from dojo.tools.burp_api.parser import BurpApiParser
from dojo.tools.burp_api.parser import convert_severity, convert_confidence


class TestParser(TestCase):
    def test_burp_without_file_has_no_findings(self):
        parser = BurpApiParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_example_report(self):
        testfile = 'dojo/unittests/scans/burp_suite_pro/example.json'
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        with open(testfile) as f:
            parser = BurpApiParser(f, test)
        self.assertIsNotNone(test.title)
        self.assertEqual(5, len(parser.items))
        i = None
        with self.subTest(i=0):
            item = parser.items[i]
            self.assertEqual('Info', item.severity)
            self.assertEqual('TLS cookie without secure flag set', item.title)
            self.assertEqual('5605602767570803712', item.unique_id_from_tool)
            self.assertEqual('5243392', item.vuln_id_from_tool)
            self.assertGreater(2, item.scanner_confidence)
            self.assertLess(6, item.scanner_confidence)

    def test_validate(self):
        testfile = 'dojo/unittests/scans/burp_suite_pro/example.json'
        with open(testfile) as f:
            test = Test()
            parser = BurpApiParser(f, test)
            for item in parser.items:
                item.full_clean()

    def test_convert_severity(self):
        severity = None
        with self.subTest(severity='info'):
            self.assertEqual("Info", convert_severity({'severity': 'info'}))

    def test_convert_confidence(self):
        confidence = None
        with self.subTest(confidence='firm'):
            self.assertLess(3, convert_confidence({'confidence': 'firm'}))
        with self.subTest(confidence='certain'):
            self.assertGreater(2, convert_confidence({'confidence': 'certain'}))
            self.assertLess(6, convert_confidence({'confidence': 'certain'}))
        with self.subTest(confidence='tentative'):
            self.assertGreater(5, convert_confidence({'confidence': 'tentative'}))
        with self.subTest(confidence='undefined'):
            self.assertIsNone(convert_confidence({'confidence': 'undefined'}))
        with self.subTest(confidence=None):
            self.assertIsNone(convert_confidence({}))
