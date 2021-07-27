from django.test import TestCase
from dojo.tools.njsscan.parser import NjsscanParser
from dojo.models import Test


class TestNjsscanParser(TestCase):

    def test_parse_no_findings(self):
        testfile = open("dojo/unittests/scans/njsscan/no_findings.json")
        parser = NjsscanParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parse_many_nodejs_findings(self):
        testfile = open("dojo/unittests/scans/njsscan/many_nodejs_findings.json")
        parser = NjsscanParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(8, len(findings))

        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("express_xss", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(79, finding.cwe)

        with self.subTest(i=1):
            finding = findings[1]
            self.assertEqual("hardcoded_jwt_secret", finding.title)
