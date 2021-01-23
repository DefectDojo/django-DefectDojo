from django.test import TestCase
from dojo.tools.acunetix.parser import AcunetixScannerParser
from dojo.models import Test


class TestAcunetixScannerParser(TestCase):

    def test_parse_without_file(self):
        parser = AcunetixScannerParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_one_finding(self):
        testfile = open("dojo/unittests/scans/acunetix/one_finding.xml")
        parser = AcunetixScannerParser(testfile, Test())
        self.assertEqual(1, len(parser.items))

    def test_parse_file_with_multiple_finding(self):
        testfile = open("dojo/unittests/scans/acunetix/many_findings.xml")
        parser = AcunetixScannerParser(testfile, Test())
        self.assertEqual(4, len(parser.items))
