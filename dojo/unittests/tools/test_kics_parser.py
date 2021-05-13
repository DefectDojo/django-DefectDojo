from django.test import TestCase
from dojo.tools.kics.parser import KICSParser
from dojo.models import Test


class TestKICSParser(TestCase):

    def test_parse_no_findings(self):
        testfile = open("dojo/unittests/scans/kics/no_findings.json")
        parser = KICSParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_many_findings(self):
        testfile = open("dojo/unittests/scans/kics/many_findings.json")
        parser = KICSParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(13, len(findings))
