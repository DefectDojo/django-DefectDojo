from unittests.dojo_test_case import DojoTestCase
from dojo.tools.govulncheck.parser import GovulncheckParser
from dojo.models import Test


class TestGovulncheckParser(DojoTestCase):

    def test_parse_no_empty(self):
        testfile = open("unittests/scans/govulncheck/empty.json", "rb")
        parser = GovulncheckParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_no_findings(self):
        testfile = open("unittests/scans/govulncheck/no_vuln.json", "rb")
        parser = GovulncheckParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_many_findings(self):
        testfile = open("unittests/scans/govulncheck/many_vuln.json", "rb")
        parser = GovulncheckParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        self.assertEqual(2, len(findings))

        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("GO-2022-1039", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertEqual("CVE-2022-41715", finding.cve)
            self.assertEqual("stdlib", finding.component_name)
            self.assertEqual("https://pkg.go.dev/vuln/GO-2022-1039", finding.url)
            self.assertIsNotNone(finding.impact)
            self.assertIsNotNone(finding.description)
            self.assertIsNotNone("https://go.dev/issue/55949", finding.references)

        with self.subTest(i=1):
            finding = findings[1]
            self.assertEqual("GO-2022-0969", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertEqual("CVE-2022-27664", finding.cve)
            self.assertEqual("stdlib", finding.component_name)
            self.assertEqual("https://pkg.go.dev/vuln/GO-2022-0969", finding.url)
            self.assertIsNotNone(finding.impact)
            self.assertIsNotNone(finding.description)
            self.assertEqual("https://groups.google.com/g/golang-announce/c/x49AQzIVX-s", finding.references)



