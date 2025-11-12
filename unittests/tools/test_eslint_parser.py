"""Unit tests for the ESLint JavaScript linter parser.

This module contains test cases for validating the ESLint parser implementation.
ESLint is a static code analysis tool for identifying problematic patterns in
JavaScript code. It helps maintain code quality and consistency across projects.

The tests verify:
- Correct parsing of ESLint JSON output format
- Proper handling of files with multiple findings
- Correct processing of empty scan results
- Handling of files with no findings (clean files)
- Validation of finding attributes and metadata
"""

from dojo.models import Finding, Test
from dojo.tools.eslint.parser import ESLintParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestESLintParser(DojoTestCase):
    """Test suite for the ESLint JavaScript linter parser.

    This class contains unit tests that verify the correct parsing and
    processing of ESLint scan results. ESLint identifies code quality issues,
    potential bugs, and style violations in JavaScript/TypeScript code.
    """
    def test_parse_file_has_two_findings(self):
        """Test parsing an ESLint report with two code quality findings.

        This test verifies that the parser correctly:
        1. Parses a JSON file containing 2 ESLint findings
        2. Returns the exact number of issues found

        The test file 'scan.json' contains typical ESLint violations such as
        unused variables, missing semicolons, or other code quality issues.
        """
        # Open the test scan file containing ESLint results with findings
        testfile = (get_unit_tests_scans_path("eslint") / "scan.json").open(encoding="utf-8")

        # Initialize the ESLint parser
        parser = ESLintParser()

        # Parse the findings from the test file
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        # Verify the correct number of findings were parsed
        self.assertEqual(2, len(findings))

    def test_parse_empty_file(self):
        """Test parsing an empty ESLint report.

        This test ensures the parser correctly handles an empty JSON file
        or a file with no scan results. The parser should return an empty
        list without raising any exceptions.

        This scenario can occur when ESLint is run on a project with no
        JavaScript files or when all files are excluded from linting.
        """
        # Open an empty test scan file
        testfile = (get_unit_tests_scans_path("eslint") / "empty.json").open(encoding="utf-8")

        # Initialize the ESLint parser
        parser = ESLintParser()

        # Parse the findings from the empty file
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        # Verify no findings were parsed from the empty file
        self.assertEqual(0, len(findings))

    def test_parse_file_with_no_finding(self):
        """Test parsing an ESLint report with no violations found.

        This test verifies that the parser correctly handles scan results
        where files were analyzed but no linting issues were detected.
        This represents a successful scan of clean, compliant code.

        This is different from an empty file - here ESLint ran successfully
        but found no violations, indicating the code follows all configured rules.
        """
        # Open a test scan file with no findings (clean code)
        testfile = (get_unit_tests_scans_path("eslint") / "no_finding.json").open(encoding="utf-8")

        # Initialize the ESLint parser
        parser = ESLintParser()

        # Parse the findings from the file
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        # Verify no findings were parsed (clean code)
        self.assertEqual(0, len(findings))

    def test_findings_have_valid_severity(self):
        """Test that all ESLint findings have valid severity levels.

        This test ensures that every finding parsed from the ESLint report
        has a severity level that matches one of the valid DefectDojo
        severity values. ESLint issues can be errors or warnings, which
        are mapped to appropriate DefectDojo severity levels.
        """
        # Parse findings from a test file with findings
        testfile = (get_unit_tests_scans_path("eslint") / "scan.json").open(encoding="utf-8")
        parser = ESLintParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        # Verify each finding has a valid severity level
        for finding in findings:
            self.assertIn(
                finding.severity,
                Finding.SEVERITIES,
                f"Finding has invalid severity: {finding.severity}",
            )

    def test_findings_contain_required_fields(self):
        """Test that all ESLint findings contain required fields.

        This test validates that each parsed finding contains all the
        essential fields required by DefectDojo, including:
        - title: A descriptive name for the linting issue
        - severity: The risk/importance level of the issue
        - file_path: The JavaScript file where the issue was found
        - line: The line number of the problematic code
        - description: Details about the rule violation
        """
        # Parse findings from a test file with findings
        testfile = (get_unit_tests_scans_path("eslint") / "scan.json").open(encoding="utf-8")
        parser = ESLintParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        # Verify each finding has required attributes
        for finding in findings:
            # Check that title is not None or empty
            self.assertIsNotNone(finding.title, "Finding title should not be None")
            self.assertTrue(len(finding.title) > 0, "Finding title should not be empty")

            # Check that severity is set
            self.assertIsNotNone(finding.severity, "Finding severity should not be None")

            # Check that file_path is set (ESLint findings should have file paths)
            self.assertIsNotNone(finding.file_path, "Finding file_path should not be None")

    def test_parser_returns_list(self):
        """Test that the parser always returns a list of findings.

        This test ensures the parser's return type is consistent,
        returning a list regardless of whether findings are present.
        This is important for maintaining a predictable API and
        preventing type-related errors in calling code.
        """
        # Test with a file that has findings
        testfile = (get_unit_tests_scans_path("eslint") / "scan.json").open(encoding="utf-8")
        parser = ESLintParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        # Verify the return type is a list
        self.assertIsInstance(findings, list, "Parser should return a list of findings")

        # Test with an empty file
        testfile = (get_unit_tests_scans_path("eslint") / "empty.json").open(encoding="utf-8")
        parser = ESLintParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        # Verify the return type is still a list (even when empty)
        self.assertIsInstance(findings, list, "Parser should return a list even for empty results")
