from dojo.models import Test
from dojo.tools.opf.parser import OPFParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestOPFParser(DojoTestCase):

    def test_opf_parser_no_findings(self):
        with (get_unit_tests_scans_path("opf") / "no_findings.json").open(encoding="utf-8") as testfile:
            parser = OPFParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_opf_parser_many_findings(self):
        with (get_unit_tests_scans_path("opf") / "many_findings.json").open(encoding="utf-8") as testfile:
            parser = OPFParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(4, len(findings))

            # Critical finding with full detail
            critical = findings[0]
            self.assertEqual("SQL injection in the report search endpoint", critical.title)
            self.assertEqual("Critical", critical.severity)
            self.assertEqual(89, critical.cwe)
            self.assertEqual(9.8, critical.cvssv3_score)
            self.assertIn("CVSS:3.1", critical.cvssv3)
            self.assertEqual("Use parameterised queries.", critical.mitigation)
            # HTML in the OPF description is flattened to text
            self.assertNotIn("<p>", critical.description)
            self.assertIn("concatenated", critical.description)

            # High finding with a CWE but no CVSS vector
            high = findings[1]
            self.assertEqual("High", high.severity)
            self.assertEqual(200, high.cwe)
            self.assertEqual(7.5, high.cvssv3_score)

            # Medium/Low findings carry no CVSS score at all
            self.assertEqual("Medium", findings[2].severity)
            self.assertEqual("Low", findings[3].severity)

    def test_opf_parser_severity_and_tags(self):
        with (get_unit_tests_scans_path("opf") / "many_findings.json").open(encoding="utf-8") as testfile:
            parser = OPFParser()
            findings = parser.get_findings(testfile, Test())
            severities = {finding.severity for finding in findings}
            self.assertEqual({"Critical", "High", "Medium", "Low"}, severities)
            # OWASP / testType / MITRE ride along as tags on the critical finding
            self.assertIn("A03:2021 Injection", findings[0].unsaved_tags)
