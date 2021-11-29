from ..dojo_test_case import DojoTestCase
from dojo.tools.nessus_was.parser import NessusWASXMLParser, NessusWASCSVParser
from dojo.models import Finding, Test, Engagement, Product


class TestNessusWASParser(DojoTestCase):

    def create_test(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        return test

    def test_parse_many_findings_xml(self):
        testfile = open("unittests/scans/nessus_was/nessus_was_many_vuln.xml")
        parser = NessusWASXMLParser()
        findings = parser.get_findings(testfile, self.create_test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(5, len(findings))
        for i in [0, 1, 2, 3, 4]:
            finding = findings[i]
            self.assertEqual('http', finding.unsaved_endpoints[0].protocol)
            self.assertIsNone(finding.cwe)
        finding = findings[0]
        self.assertEqual('High', finding.severity)
        self.assertEqual('Cross-Site Scripting (XSS)', finding.title)

    def test_parse_one_findings_xml(self):
        testfile = open("unittests/scans/nessus_was/nessus_was_one_vuln.xml")
        parser = NessusWASXMLParser()
        findings = parser.get_findings(testfile, self.create_test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual('http', finding.unsaved_endpoints[0].protocol)
        self.assertIsNone(finding.cwe)
        self.assertEqual('High', finding.severity)
        self.assertEqual('Cross-Site Scripting (XSS)', finding.title)

    def test_parse_no_findings_xml(self):
        testfile = open("unittests/scans/nessus_was/nessus_was_no_vuln.xml")
        parser = NessusWASXMLParser()
        findings = parser.get_findings(testfile, self.create_test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(0, len(findings))

    def test_parse_many_findings_csv(self):
        testfile = open("unittests/scans/nessus_was/nessus_was_many_vuln.csv")
        parser = NessusWASCSVParser()
        findings = parser.get_findings(testfile, self.create_test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(5, len(findings))
        for i in [0, 1, 2, 3, 4]:
            finding = findings[i]
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertEqual('google.com', finding.unsaved_endpoints[0].host)
            self.assertIsNone(finding.cve)
        finding = findings[0]
        self.assertEqual('7.1', finding.cvssv3_score)
        self.assertEqual('High', finding.severity)
        self.assertEqual('http', finding.unsaved_endpoints[0].protocol)

    def test_parse_one_findings_csv(self):
        testfile = open("unittests/scans/nessus_was/nessus_was_one_vuln.csv")
        parser = NessusWASCSVParser()
        findings = parser.get_findings(testfile, self.create_test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual('google.com', finding.unsaved_endpoints[0].host)
        self.assertIsNone(finding.cve)
        self.assertEqual('7.1', finding.cvssv3_score)
        self.assertEqual('High', finding.severity)
        self.assertEqual('http', finding.unsaved_endpoints[0].protocol)

    def test_parse_no_findings_csv(self):
        testfile = open("unittests/scans/nessus_was/nessus_was_no_vuln.csv")
        parser = NessusWASCSVParser()
        findings = parser.get_findings(testfile, self.create_test())
        self.assertEqual(0, len(findings))
