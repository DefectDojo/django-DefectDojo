from ..dojo_test_case import DojoTestCase
from dojo.tools.api_msdefender.parser import ApiMSDefenderParser
from dojo.models import Test


class TestAPIMSDefenderAPIParser(DojoTestCase):

    def test_parse_many_findings(self):
        testfile = open("unittests/scans/api_msdefender/report_many_vulns.json")
        parser = ApiMSDefenderParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(4, len(findings))
        finding = findings[2]
        self.assertEqual("High", finding.severity)
        self.assertEqual("fjeiwofjweoifjwefo-_-CVE-1234-56788-_-packagvendor-_-tools-_-1.2.3.4-_-", finding.title)

    def test_parse_one_finding(self):
        testfile = open("unittests/scans/api_msdefender/report_one_vuln.json")
        parser = ApiMSDefenderParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("Low", finding.severity)
        self.assertEqual("fjeiwofjweoifjwefo-_-CVE-1234-5678-_-packagvendor-_-tools-_-1.2.3.4-_-", finding.title)
        self.assertEqual("CVE-1234-5678", finding.cve)

    def test_parse_no_finding(self):
        testfile = open("unittests/scans/api_msdefender/report_no_vuln.json")
        parser = ApiMSDefenderParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))
