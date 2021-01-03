from django.test import TestCase

from dojo.models import Test
from dojo.tools.burp_api.parser import BurpApiParser
from dojo.tools.burp_api.parser import convert_severity, convert_confidence


class TestParser(TestCase):
    def test_burp_without_file_has_no_findings(self):
        parser = BurpApiParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_example_report(self):
        testfile = 'dojo/unittests/scans/burp_suite_pro/example.json'
        test = Test()
        with open(testfile) as f:
            parser = BurpApiParser(f, test)
        self.assertIsNotNone(test.title)
        self.assertEqual(5, len(parser.items))
        item = parser.items[0]
        self.assertEqual('Info', item.severity)
        self.assertEqual('TLS cookie without secure flag set', item.title)
        self.assertEqual('5605602767570803712', item.unique_id_from_tool)
        self.assertEqual('5243392', item.vuln_id_from_tool)

    def test_convert_severity(self):
        self.assertEqual("Info", convert_severity({'severity': 'info'}))
    
    def test_convert_confidence(self):
        with self.subTest(confidence='firm'):
            self.assertLess(3, convert_confidence({'confidence': confidence}))
        with self.subTest(confidence='certain'):
            self.assertGreater(2, convert_confidence({'confidence': confidence}))
            self.assertLess(6, convert_confidence({'confidence': confidence}))
        with self.subTest(confidence='tentative'):
            self.assertGreater(5, convert_confidence({'confidence': confidence}))
        with self.subTest(confidence='undefined'):
            self.assertIsNone(convert_confidence({'confidence': confidence}))
        with self.subTest(confidence=None):
            self.assertIsNone(convert_confidence({'confidence': confidence}))
