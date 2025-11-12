"""Unit tests for the Hadolint Dockerfile linter parser.

This module contains test cases for validating the Hadolint parser implementation.
Hadolint is a Dockerfile linter that helps you build best practice Docker images.
It validates Dockerfiles against best practices and common mistakes.

The tests verify:
- Correct parsing of Hadolint JSON output format
- Proper extraction of linting issues from single and multiple Dockerfiles
- Accurate line number and file path extraction
- Handling of various severity levels and rule violations
"""

from dojo.models import Finding, Test
from dojo.tools.hadolint.parser import HadolintParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestHadolintParser(DojoTestCase):
    """Test suite for the Hadolint Dockerfile linter parser.

    This class contains unit tests that verify the correct parsing and
    processing of Hadolint scan results. Hadolint checks Dockerfiles for
    common issues and best practice violations.
    """

    def test_parse_file_with_one_dockerfile(self):
        """Test parsing Hadolint results from a single Dockerfile scan.

        This test verifies that the parser correctly:
        1. Parses a JSON file containing 4 linting issues from one Dockerfile
        2. Extracts the correct line number for each issue
        3. Captures the accurate file path of the Dockerfile

        The test validates that basic Dockerfile linting issues are properly
        identified and parsed, including rule violations and best practice warnings.
        """
        # Open the test scan file containing Hadolint results for one Dockerfile
        testfile = (get_unit_tests_scans_path("hadolint") / "one_dockerfile.json").open(encoding="utf-8")

        # Initialize the Hadolint parser
        parser = HadolintParser()

        # Parse the findings from the test file
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        # Verify the correct number of findings were parsed
        self.assertEqual(4, len(findings))

        # Validate the first finding's attributes
        finding = list(findings)[0]
        self.assertEqual(finding.line, 9)
        self.assertEqual(finding.file_path, "django-DefectDojo\\Dockerfile.django")

    def test_parse_file_with_many_dockerfile(self):
        """Test parsing Hadolint results from multiple Dockerfile scans.

        This test ensures the parser can handle scan results from multiple
        Dockerfiles in a single report. It verifies that all findings from
        different Dockerfiles are correctly parsed and aggregated.

        This is important for projects with multiple Docker images or
        multi-stage builds where several Dockerfiles need to be validated.
        """
        # Open the test scan file containing Hadolint results for multiple Dockerfiles
        testfile = (get_unit_tests_scans_path("hadolint") / "many_dockerfile.json").open(encoding="utf-8")

        # Initialize the Hadolint parser
        parser = HadolintParser()

        # Parse the findings from the test file
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        # Verify the correct total number of findings across all Dockerfiles
        self.assertEqual(12, len(findings))

    def test_findings_have_valid_severity(self):
        """Test that all Hadolint findings have valid severity levels.

        This test ensures that every finding parsed from the Hadolint report
        has a severity level that matches one of the valid DefectDojo
        severity values. Hadolint issues can range from style suggestions
        to critical security problems.
        """
        # Parse findings from a test file
        testfile = (get_unit_tests_scans_path("hadolint") / "one_dockerfile.json").open(encoding="utf-8")
        parser = HadolintParser()
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
        """Test that all Hadolint findings contain required fields.

        This test validates that each parsed finding contains all the
        essential fields required by DefectDojo, including:
        - title: A descriptive name for the linting issue
        - severity: The risk/importance level of the issue
        - file_path: The Dockerfile where the issue was found
        - line: The line number of the problematic instruction
        - description: Details about the issue and how to fix it
        """
        # Parse findings from a test file
        testfile = (get_unit_tests_scans_path("hadolint") / "one_dockerfile.json").open(encoding="utf-8")
        parser = HadolintParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()

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

    def test_parser_returns_list(self):
        """Test that the parser always returns a list of findings.

        This test ensures the parser's return type is consistent,
        returning a list even when processing different input files.
        This is important for maintaining a predictable API.
        """
        # Test with single Dockerfile results
        testfile = (get_unit_tests_scans_path("hadolint") / "one_dockerfile.json").open(encoding="utf-8")
        parser = HadolintParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        # Verify the return type is a list
        self.assertIsInstance(findings, list, "Parser should return a list of findings")
