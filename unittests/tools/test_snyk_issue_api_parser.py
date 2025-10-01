from pathlib import Path

from django.test import TestCase

from dojo.models import Test
from dojo.tools.snyk_issue_api.parser import SnykIssueApiParser


class TestSnykIssueApiParser(TestCase):
    def test_parse_no_findings(self):
        with Path("unittests/scans/snyk_issue_api/empty.json").open(encoding="utf-8") as testfile:
            parser = SnykIssueApiParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_many_findings(self):
        with Path("unittests/scans/snyk_issue_api/snyk_code_scan_api_many_vuln.json").open(encoding="utf-8") as testfile:
            parser = SnykIssueApiParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

            # Verify first finding
            finding = findings[0]
            self.assertEqual("Cross-Site Request Forgery (CSRF)", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("Cross-Site Request Forgery (CSRF)", finding.description)
            self.assertEqual("path/path/file.abc", finding.file_path)
            self.assertEqual(65, finding.line)
            self.assertEqual(352, finding.cwe)
            self.assertEqual("3916a413-2fca-45c9-a1bf-a1373258fe69", finding.unique_id_from_tool)
            self.assertEqual(False, finding.false_p)
            self.assertEqual(True, finding.active)
            self.assertEqual(True, finding.verified)
            self.assertEqual(True, finding.static_finding)
            self.assertEqual(False, finding.dynamic_finding)
            self.assertIn("Risk Score: 829", finding.severity_justification)
            # Check fix_available if the field exists
            if hasattr(finding, "fix_available"):
                self.assertEqual(False, finding.fix_available)

            # Verify second finding
            finding = findings[1]
            self.assertEqual("Cross-site Scripting (XSS)", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(79, finding.cwe)
            self.assertEqual(True, finding.out_of_scope)  # This one is ignored
            # Check fix_available if the field exists
            if hasattr(finding, "fix_available"):
                self.assertEqual(False, finding.fix_available)

            # Verify third finding
            finding = findings[2]
            self.assertEqual("Use of Hardcoded Passwords", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual(259, finding.cwe)
            self.assertEqual("Additional CWEs: CWE-798", finding.references)  # Has multiple CWEs
            # Check fix_available if the field exists
            if hasattr(finding, "fix_available"):
                self.assertEqual(False, finding.fix_available)
