from dojo.models import Test
from dojo.tools.gosec.parser import GosecParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestGosecParser(DojoTestCase):

    def test_parse_file_with_one_finding(self):
        with (get_unit_tests_scans_path("gosec") / "many_vulns.json").open(encoding="utf-8") as testfile:
            parser = GosecParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(28, len(findings))

            # Test first finding with CWE
            finding = findings[0]
            self.assertEqual("Low", finding.severity)
            self.assertEqual("/vagrant/go/src/govwa/app.go", finding.file_path)
            self.assertEqual(79, finding.line)
            self.assertEqual(252, finding.cwe)
            self.assertEqual("https://cwe.mitre.org/data/definitions/252.html", finding.references)

            # Test finding without CWE (should fallback to gosec docs)
            finding_no_cwe = findings[2]
            self.assertIsNone(finding_no_cwe.cwe)
            self.assertEqual("https://securego.io/docs/rules/g104.html", finding_no_cwe.references)

            # Test finding with different CWE
            finding_crypto = findings[3]
            self.assertEqual(327, finding_crypto.cwe)
            self.assertEqual("https://cwe.mitre.org/data/definitions/327.html", finding_crypto.references)

            # Test SQL injection finding
            finding_sqli = findings[22]
            self.assertEqual(89, finding_sqli.cwe)
            self.assertEqual("https://cwe.mitre.org/data/definitions/89.html", finding_sqli.references)
