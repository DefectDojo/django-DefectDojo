from django.test import TestCase

from dojo.models import Test
from dojo.tools.semgrep_pro.parser import SemgrepProParser
from unittests.dojo_test_case import get_unit_tests_scans_path


class TestSemgrepProParser(TestCase):
    def test_parse_no_findings(self):
        path = get_unit_tests_scans_path("semgrep_pro") / "no_vuln.json"
        with path.open(encoding="utf-8") as testfile:
            parser = SemgrepProParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        path = get_unit_tests_scans_path("semgrep_pro") / "one_vuln.json"
        with path.open(encoding="utf-8") as testfile:
            parser = SemgrepProParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

            finding = findings[0]
            # Basic fields
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("typescript.react.security.audit.react-no-refs.react-no-refs", finding.vuln_id_from_tool)
            self.assertEqual("frontend/src/corpComponents/Code.tsx", finding.file_path)
            self.assertEqual(120, finding.line)
            self.assertEqual(319, finding.cwe)  # CWE-319: Cleartext Transmission of Sensitive Information
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

            # Status fields
            self.assertTrue(finding.active)  # status is "open"
            self.assertFalse(finding.verified)  # triage_state is "untriaged"

            # Description field - check for key components
            self.assertIsNotNone(finding.description)
            self.assertIn("Message:", finding.description)
            self.assertIn("Rule Message:", finding.description)
            self.assertIn("CWE References:", finding.description)
            self.assertIn("CWE-319:", finding.description)
            self.assertIn("OWASP References:", finding.description)
            self.assertIn("A03:2017", finding.description)
            self.assertIn("A02:2021", finding.description)
            self.assertIn("Categories:", finding.description)
            self.assertIn("security", finding.description)

            # Impact field - check for key components
            self.assertIsNotNone(finding.impact)
            self.assertIn("Mishandled Sensitive Information", finding.impact)
            self.assertIn("Confidence: Medium", finding.impact)
            self.assertIn("Repository: semgrep", finding.impact)

            # Mitigation field - check for key components
            self.assertIsNotNone(finding.mitigation)
            self.assertIn("**Guidance Summary:**", finding.mitigation)
            self.assertIn("template rendering engine", finding.mitigation)
            self.assertIn("**Instructions:**", finding.mitigation)
            self.assertIn("npm install ejs", finding.mitigation)
            self.assertIn("**Auto-triage Verdict:** false_positive", finding.mitigation)
            self.assertIn("**Component:** user data", finding.mitigation)
            self.assertIn("**Risk Level:** high", finding.mitigation)

            # References field - check for key components
            self.assertIsNotNone(finding.references)
            self.assertIn("Line of Code:", finding.references)
            self.assertIn("CWE-319:", finding.references)
            self.assertIn("A03:2017", finding.references)
            self.assertIn("External Ticket:", finding.references)

            # Unique identifier
            self.assertEqual("0f8c79a6f7e0ff2f908ff5bc366ae1548465069bae8892088051e1c3b4b12c6b8df37d5bcbb181eb868aa79f81f239d14bf2336d552786ab8ccdc7279adf07a6_1", finding.unique_id_from_tool)
