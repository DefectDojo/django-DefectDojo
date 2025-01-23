import unittest
import os
from dojo.tools.anchore_enterprise_vulnerabilities.parser import AnchoreEnterpriseParser
from dojo.models import Test

class TestAnchoreEnterpriseParser(unittest.TestCase):
    def test_parser_with_valid_report(self):
        testfile = 'unittests/scans/anchore_enterprise/sample_report.json'  
        test = Test()  # Create a Test instance
        
        # Ensure the test file exists
        self.assertTrue(os.path.exists(testfile), f"Test file {testfile} not found!")
        
        # Create the parser and get findings
        parser = AnchoreEnterpriseParser()
        findings = parser.get_findings(testfile, test)
        
        # Print the number of findings to check what is returned
        print(f"Number of findings: {len(findings)}")
        
        # Assert that there are findings
        self.assertGreater(len(findings), 0, "No findings found in the report!")
        
        # Optionally, dynamically check a few sample findings if needed
        # Check the first finding has the necessary attributes
        if findings:
            self.assertTrue(hasattr(findings[0], 'title'), "Finding does not have a title!")
            self.assertTrue(hasattr(findings[0], 'severity'), "Finding does not have severity!")
            self.assertTrue(hasattr(findings[0], 'description'), "Finding does not have description!")

            # Optionally, check that severity is a valid value
            valid_severities = ["Low", "Medium", "High", "Critical", "Info"]
            self.assertIn(findings[0].severity, valid_severities, f"Unexpected severity: {findings[0].severity}")

        # You can also assert a specific number of findings dynamically by modifying this part:
        expected_findings = len(findings)  # Set dynamically, or pass it as a parameter
        self.assertEqual(len(findings), expected_findings, f"Expected {expected_findings} findings, but got {len(findings)}")
