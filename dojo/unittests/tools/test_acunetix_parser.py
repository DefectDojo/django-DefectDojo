from django.test import TestCase
from dojo.tools.acunetix.parser import AcunetixParser
from dojo.models import Test


class TestAcunetixParser(TestCase):
    def test_parse_without_file(self):
        parser = AcunetixParser()
        findings = parser.get_findings(None, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_finding(self):
        testfile = open("dojo/unittests/scans/acunetix/one_finding.xml")
        parser = AcunetixParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_finding(self):
        testfile = open("dojo/unittests/scans/acunetix/many_findings.xml")
        parser = AcunetixParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(4, len(findings))
