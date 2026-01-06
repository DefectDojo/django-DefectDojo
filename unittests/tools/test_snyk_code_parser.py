from dojo.models import Test
from dojo.tools.snyk_code.parser import SnykCodeParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSnykCodeParser(DojoTestCase):

    def test_snykParser_single_has_many_findings(self):
        testfile = (get_unit_tests_scans_path("snyk_code") / "single_project_many_vulns.json").open(encoding="utf-8")
        parser = SnykCodeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(206, len(findings))

        # Test specific finding properties for the first finding
        first_finding = findings[0]
        self.assertIsNotNone(first_finding.title)
        self.assertIn("_", first_finding.title)  # Should contain ruleId_filepath format
        self.assertIn("**ruleId**:", first_finding.description)
        self.assertIn("**message**:", first_finding.description)
        self.assertIn("**score**:", first_finding.description)
        self.assertIn("**isAutofixable**:", first_finding.description)
        self.assertIn(first_finding.severity, ["Low", "Medium", "High", "Critical"])
        self.assertTrue(first_finding.static_finding)
        self.assertFalse(first_finding.dynamic_finding)

    def test_snykcode_issue_9270(self):
        with (get_unit_tests_scans_path("snyk_code") / "snykcode_issue_9270.json").open(encoding="utf-8") as testfile:
            parser = SnykCodeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(39, len(findings))

            # Test specific properties of the first finding
            first_finding = findings[0]
            self.assertEqual("javascript/XSS_frontend/src/app/score-board/score-board.component.ts", first_finding.title)
            self.assertEqual("Medium", first_finding.severity)  # priorityScore: 504 -> Medium
            self.assertTrue(first_finding.static_finding)
            self.assertFalse(first_finding.dynamic_finding)

            # Test CWE value is correctly parsed
            self.assertEqual(79, first_finding.cwe)  # CWE-79 from rule properties

            # Test description contains expected fields
            self.assertIn("**ruleId**: javascript/XSS", first_finding.description)
            self.assertIn("**ruleIndex**: 0", first_finding.description)
            self.assertIn("**score**: 504", first_finding.description)
            self.assertIn("**isAutofixable**: False", first_finding.description)
            self.assertIn("**uri**: frontend/src/app/score-board/score-board.component.ts", first_finding.description)
            self.assertIn("**startLine**: 216", first_finding.description)
            self.assertIn("**endLine**: 216", first_finding.description)
            self.assertIn("**startColumn**: 44", first_finding.description)
            self.assertIn("**endColumn**: 67", first_finding.description)

            # Test file path is correctly set
            self.assertEqual("frontend/src/app/score-board/score-board.component.ts", first_finding.file_path)

            # Test that different priority scores map to different severities
            severity_counts = {}
            for finding in findings:
                severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

            # Should have findings with different severities based on priority scores
            self.assertGreater(len(severity_counts), 1, "Should have multiple severity levels")

            # Test that all findings have the expected custom format
            for finding in findings:
                self.assertIn("_", finding.title, "Title should contain ruleId_filepath format")
                self.assertIn("**ruleId**:", finding.description, "Description should contain ruleId field")
                self.assertIn("**score**:", finding.description, "Description should contain score field")
                self.assertTrue(finding.static_finding, "All findings should be static")
                self.assertFalse(finding.dynamic_finding, "All findings should not be dynamic")
                self.assertIn(finding.severity, ["Low", "Medium", "High", "Critical"], "Severity should be valid")

            # Test CWE values are parsed correctly
            cwe_values = [finding.cwe for finding in findings if finding.cwe]
            self.assertGreater(len(cwe_values), 0, "Should have findings with CWE values")

            # Test that specific CWE values are found (based on the test data)
            self.assertIn(79, cwe_values, "Should find CWE-79 (XSS)")
            self.assertTrue(all(isinstance(cwe, int) for cwe in cwe_values), "All CWE values should be integers")

    def test_snykcode_severity_mapping(self):
        """Test that priority scores are correctly mapped to severities"""
        with (get_unit_tests_scans_path("snyk_code") / "snykcode_issue_9270.json").open(encoding="utf-8") as testfile:
            parser = SnykCodeParser()
            findings = parser.get_findings(testfile, Test())

            # Test specific severity mappings based on priority scores
            severity_score_mapping = {}
            for finding in findings:
                # Extract score from description
                desc_lines = finding.description.split("\n")
                score_line = [line for line in desc_lines if line.startswith("**score**:")]
                if score_line:
                    score = int(score_line[0].split(": ")[1])
                    severity_score_mapping[finding.severity] = severity_score_mapping.get(finding.severity, [])
                    severity_score_mapping[finding.severity].append(score)

            # Test that score ranges map to correct severities
            for severity, scores in severity_score_mapping.items():
                if severity == "Low":
                    self.assertTrue(all(score <= 399 for score in scores), f"Low severity should have scores <= 399, got {scores}")
                elif severity == "Medium":
                    self.assertTrue(all(400 <= score <= 699 for score in scores), f"Medium severity should have scores 400-699, got {scores}")
                elif severity == "High":
                    self.assertTrue(all(700 <= score <= 899 for score in scores), f"High severity should have scores 700-899, got {scores}")
                elif severity == "Critical":
                    self.assertTrue(all(score >= 900 for score in scores), f"Critical severity should have scores >= 900, got {scores}")

    def test_snykcode_cwe_parsing(self):
        """Test that CWE values are correctly parsed from Snyk Code SARIF rule properties"""
        with (get_unit_tests_scans_path("snyk_code") / "snykcode_issue_9270.json").open(encoding="utf-8") as testfile:
            parser = SnykCodeParser()
            findings = parser.get_findings(testfile, Test())

            # Test that CWE values are parsed correctly
            cwe_values = [finding.cwe for finding in findings if finding.cwe]
            self.assertGreater(len(cwe_values), 0, "Should have findings with CWE values")

            # Test that specific CWE values are found (based on the test data)
            self.assertIn(79, cwe_values, "Should find CWE-79 (XSS)")
            self.assertTrue(all(isinstance(cwe, int) for cwe in cwe_values), "All CWE values should be integers")

            # Test the first finding has the expected CWE
            first_finding = findings[0]
            self.assertEqual(79, first_finding.cwe, "First finding should have CWE-79")

            # Test that findings without CWE values are handled properly
            [finding for finding in findings if not finding.cwe]
            findings_with_cwe = [finding for finding in findings if finding.cwe]

            # Should have some findings with CWE values
            self.assertGreater(len(findings_with_cwe), 0, "Should have findings with CWE values")

            # Test that CWE values are properly extracted from rule properties
            unique_cwes = set(cwe_values)
            self.assertGreater(len(unique_cwes), 0, "Should have unique CWE values")

            # All CWE values should be valid integers
            for cwe in unique_cwes:
                self.assertIsInstance(cwe, int, f"CWE value {cwe} should be an integer")
                self.assertGreater(cwe, 0, f"CWE value {cwe} should be positive")
