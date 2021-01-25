from django.test import TestCase
from dojo.tools.nessus.parser import NessusXMLParser
from dojo.models import Test, Engagement, Product


class TestNessusParser(TestCase):

    def create_test(self):
        self.test = Test()
        self.test.engagement = Engagement()
        self.test.engagement.product = Product()

    def test_parse_without_file_has_no_findings(self):
        parser = NessusXMLParser(None, self.create_test())
        findings = parser.items
        self.assertEqual(0, len(findings))

    def test_parse_some_findings(self):
        testfile = open("dojo/unittests/scans/nessus/nessus_many_vuln.xml")
        parser = NessusXMLParser(None, self.create_test())
        findings = parser.items
        self.assertEqual(6, len(findings))
        finding = findings[0]
        self.assertEqual('Info', finding.severity)
        self.assertEqual('Info', finding.cwe)
