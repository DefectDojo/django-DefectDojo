import io
import json

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

    def test_opf_parser_cvss_v4_vector_routes_to_cvssv4(self):
        # A CVSS v4 vector must land in cvssv4 (with a derived score), not raw in cvssv3.
        doc = {
            "opfVersion": "1.1",
            "findings": [
                {
                    "title": "SSRF in the webhook sender",
                    "severity": "high",
                    "cvssVector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                },
            ],
        }
        parser = OPFParser()
        findings = parser.get_findings(io.StringIO(json.dumps(doc)), Test())
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertIn("CVSS:4.0", finding.cvssv4)
        self.assertIsNotNone(finding.cvssv4_score)
        # v4 vector must not be mislabeled into the v3 field
        self.assertFalse(finding.cvssv3)

    def test_opf_parser_decodes_full_html_entity_set(self):
        # Entities beyond the old hand-rolled map (numeric refs, &apos;) must decode.
        doc = {
            "opfVersion": "1.1",
            "findings": [
                {
                    "title": "Entity handling",
                    "severity": "low",
                    "impact": "It&#8217;s the user&apos;s caf&#233; &#x27;else&#x27;.",
                },
            ],
        }
        parser = OPFParser()
        findings = parser.get_findings(io.StringIO(json.dumps(doc)), Test())
        impact = findings[0].impact
        self.assertNotIn("&", impact)  # no entity codes leak through
        self.assertIn("café", impact)
        self.assertIn("user's", impact)
        self.assertIn("'else'", impact)
