from os import path

from django.test import TestCase
from dojo.models import Test
from dojo.tools.skf.parser import SKFParser


class TestSkfParser(TestCase):

    def test_single_has_no_finding(self):
        testfile = open(path.join(path.dirname(__file__), "scans/skf/export.csv"))
        parser = SKFParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(27, len(findings))
        # finding 0
        finding = findings[0]
        self.assertEqual("Authentication Verification Requirements : Verify that user set passwords are at least 12 characters in length. (C6)", finding.title)
        self.assertEqual("Info", finding.severity)
