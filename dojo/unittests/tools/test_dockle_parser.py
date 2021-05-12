from django.test import TestCase
from dojo.tools.dockle.parser import DockleParser
from dojo.models import Test


class TestDockleParser(TestCase):

    def test_parse_no_findings(self):
        testfile = open("dojo/unittests/scans/dockle/no_findings.json")
        parser = DockleParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_many_findings(self):
        testfile = open("dojo/unittests/scans/dockle/many_findings.json")
        parser = DockleParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(3, len(findings))
