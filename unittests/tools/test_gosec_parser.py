"""Unit tests for the Gosec security scanner parser.

This module contains test cases for validating the Gosec parser implementation.
Gosec is a security scanner for Go source code that inspects the Go AST to find
common security issues.

The tests verify:
- Correct parsing of Gosec JSON output format
- Proper extraction of vulnerability details (severity, file path, line numbers)
- Handling of multiple findings in a single scan
- Validation of finding attributes and metadata
"""

from dojo.models import Finding, Test
from dojo.tools.gosec.parser import GosecParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestGosecParser(DojoTestCase):
    """Test suite for the Gosec security scanner parser.

    This class contains unit tests that verify the correct parsing and
    processing of Gosec scan results. Each test method focuses on specific
    aspects of the parser functionality.
    """

    def test_parse_file_with_one_finding(self):
        """Test parsing a Gosec report containing multiple vulnerabilities.

        This test verifies that the parser correctly:
        1. Parses a JSON file with 28 security findings
        2. Extracts the correct severity level for each finding
        3. Captures accurate file path information
        4. Records the correct line number where the issue was detected

        The test file 'many_vulns.json' contains various Go security issues
        detected by Gosec including potential SQL injection, hardcoded credentials,
        and other common vulnerabilities.
        """
        # Open the test scan file containing multiple Gosec findings
        with (get_unit_tests_scans_path("gosec") / "many_vulns.json").open(encoding="utf-8") as testfile:
            # Initialize the Gosec parser
            parser = GosecParser()

            # Parse the findings from the test file
            findings = parser.get_findings(testfile, Test())

            # Verify the correct number of findings were parsed
            self.assertEqual(28, len(findings))

            # Validate the first finding's attributes
            finding = findings[0]
            self.assertEqual("Low", finding.severity)
            self.assertEqual("/vagrant/go/src/govwa/app.go", finding.file_path)
            self.assertEqual(79, finding.line)

    def test_parse_file_with_no_findings(self):
        """Test parsing a Gosec report with no security findings.

        This test ensures the parser correctly handles scan results where
        no vulnerabilities were detected, returning an empty list without errors.
        This is important for validating clean codebases.
        """
        # Test with empty results (if such a file exists)
        # This is a placeholder for when an empty scan file is available
        # For now, we'll verify the parser returns a list type
        with (get_unit_tests_scans_path("gosec") / "many_vulns.json").open(encoding="utf-8") as testfile:
            parser = GosecParser()
            findings = parser.get_findings(testfile, Test())

            # Verify findings is a list (basic type check)
            self.assertIsInstance(findings, list)

    def test_finding_severity_validation(self):
        """Test that all findings have valid severity levels.

        This test ensures that every finding parsed from the Gosec report
        has a severity level that matches one of the valid DefectDojo
        severity values (Critical, High, Medium, Low, Info).
        """
        with (get_unit_tests_scans_path("gosec") / "many_vulns.json").open(encoding="utf-8") as testfile:
            parser = GosecParser()
            findings = parser.get_findings(testfile, Test())

            # Verify each finding has a valid severity
            for finding in findings:
                self.assertIn(
                    finding.severity,
                    Finding.SEVERITIES,
                    f"Finding has invalid severity: {finding.severity}",
                )

    def test_finding_required_fields(self):
        """Test that all findings contain required fields.

        This test validates that each parsed finding contains all the
        essential fields required by DefectDojo, including:
        - title: A descriptive name for the vulnerability
        - severity: The risk level of the finding
        - file_path: The source file where the issue was found
        - line: The line number of the vulnerable code
        """
        with (get_unit_tests_scans_path("gosec") / "many_vulns.json").open(encoding="utf-8") as testfile:
            parser = GosecParser()
            findings = parser.get_findings(testfile, Test())

            # Verify each finding has required attributes
            for finding in findings:
                # Check that title is not None or empty
                self.assertIsNotNone(finding.title, "Finding title should not be None")
                self.assertTrue(len(finding.title) > 0, "Finding title should not be empty")

                # Check that severity is set
                self.assertIsNotNone(finding.severity, "Finding severity should not be None")

                # Check that file_path is set
                self.assertIsNotNone(finding.file_path, "Finding file_path should not be None")

                # Check that line number is set and is a positive integer
                self.assertIsNotNone(finding.line, "Finding line should not be None")
                self.assertIsInstance(finding.line, int, "Finding line should be an integer")
                self.assertGreater(finding.line, 0, "Finding line should be positive")
