from unittests.dojo_test_case import DojoTestCase
from dojo.tools.govulncheck.parser import GovulncheckParser
from dojo.models import Test


class TestGovulncheckParser(DojoTestCase):

    def test_parse_empty(self):
        with self.assertRaises(ValueError) as exp:
            testfile = open("unittests/scans/govulncheck/empty.json")
            parser = GovulncheckParser()
            findings = parser.get_findings(testfile, Test())
            self.assertTrue(
                "Invalid JSON format" in str(exp.exception)
            )

    def test_parse_no_findings(self):
        testfile = open("unittests/scans/govulncheck/no_vulns.json")
        parser = GovulncheckParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_many_findings(self):
        testfile = open("unittests/scans/govulncheck/many_vulns.json")
        parser = GovulncheckParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        self.assertEqual(3, len(findings))

        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("GO-2022-1144", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertEqual("CVE-2022-41717", finding.cve)
            self.assertEqual("stdlib", finding.component_name)
            self.assertEqual("v1.19.0", finding.component_version)
            self.assertEqual("GO-2022-1144", finding.unique_id_from_tool)
            self.assertEqual("https://pkg.go.dev/vuln/GO-2022-1144", finding.url)
            self.assertIsNotNone(finding.impact)
            self.assertIsNotNone(finding.description)
            self.assertEqual("https://go.dev/issue/56350", finding.references)

        with self.subTest(i=1):
            finding = findings[1]
            self.assertEqual("GO-2022-1143", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertEqual("CVE-2022-41720", finding.cve)
            self.assertEqual("stdlib", finding.component_name)
            self.assertEqual("v1.19.0", finding.component_version)
            self.assertEqual("GO-2022-1143", finding.unique_id_from_tool)
            self.assertEqual("https://pkg.go.dev/vuln/GO-2022-1143", finding.url)
            self.assertIsNotNone(finding.impact)
            self.assertIsNotNone(finding.description)
            self.assertEqual("https://go.dev/issue/56694", finding.references)

        with self.subTest(i=2):
            finding = findings[2]
            self.assertEqual("GO-2022-0969", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertEqual("CVE-2022-27664", finding.cve)
            self.assertEqual("stdlib", finding.component_name)
            self.assertEqual("v1.19.0", finding.component_version)
            self.assertEqual("GO-2022-0969", finding.unique_id_from_tool)
            self.assertEqual("https://pkg.go.dev/vuln/GO-2022-0969", finding.url)
            self.assertIsNotNone(finding.impact)
            self.assertIsNotNone(finding.description)
            self.assertEqual("https://groups.google.com/g/golang-announce/c/x49AQzIVX-s", finding.references)
