from django.test import TestCase
from dojo.tools.zap.parser import ZapXmlParser
from dojo.models import Test, Engagement, Product


class TestZAPXML(TestCase):

    def setUp(self):
        self.test = Test()
        self.test.engagement = Engagement()
        self.test.engagement.product = Product()

    def test_parse_without_file_has_no_findings(self):
        parser = ZapXmlParser(None, self.test)
        self.assertEqual(0, len(parser.items))

    def test_parse_no_findings(self):
        testfile = open("dojo/unittests/scans/zap/empty_2.9.0.xml")
        parser = ZapXmlParser(testfile, self.test)
        self.assertEqual(0, len(parser.items))

    def test_parse_some_findings(self):
        testfile = open("dojo/unittests/scans/zap/some_2.9.0.xml")
        parser = ZapXmlParser(testfile, self.test)
        self.assertEqual(7, len(parser.items))
