import json
import sys
from types import ModuleType
import unittest
from unittest.mock import MagicMock

# Mock dojo dependencies for standalone testing
if "dojo.models" not in sys.modules:
    dojo_models = ModuleType("dojo.models")
    class MockFinding:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
    dojo_models.Finding = MockFinding
    sys.modules["dojo.models"] = dojo_models

if "dojo.celery" not in sys.modules:
    dojo_celery = ModuleType("dojo.celery")
    dojo_celery.app = MagicMock()
    sys.modules["dojo.celery"] = dojo_celery

from dojo.tools.oscal.parser import OscalParser


class TestOscalParser(unittest.TestCase):
    def setUp(self):
        self.parser = OscalParser()
        self.test = MagicMock()

    def test_oscal_assessment_results_parsing(self):
        sample_oscal = {
            "assessment-results": {
                "metadata": {
                    "title": "Prowler Cloud Security Assessment Results",
                    "oscal-version": "1.2.3",
                },
                "results": [
                    {
                        "uuid": "res-1234-5678",
                        "title": "AWS Assessment Scan",
                        "observations": [
                            {
                                "uuid": "obs-001",
                                "title": "Check s3_bucket_public_access_block",
                                "description": "S3 bucket has public access block disabled",
                            }
                        ],
                        "findings": [
                            {
                                "uuid": "find-001",
                                "title": "Ensure S3 bucket public access block is enabled",
                                "description": "S3 bucket test-bucket allows public read",
                                "target": {
                                    "target-id": "arn:aws:s3:::test-bucket",
                                    "status": "fail",
                                },
                                "related-observations": [
                                    {"observation-uuid": "obs-001"}
                                ],
                                "props": [
                                    {"name": "severity", "value": "high"},
                                    {"name": "control_id", "value": "AC-3"},
                                    {"name": "check_id", "value": "s3_bucket_public_access_block"},
                                ],
                            }
                        ],
                    }
                ],
            }
        }

        findings = self.parser.get_findings(json.dumps(sample_oscal), self.test)
        self.assertEqual(len(findings), 1)
        finding = findings[0]

        self.assertEqual(finding.title, "Ensure S3 bucket public access block is enabled")
        self.assertEqual(finding.severity, "High")
        self.assertTrue(finding.active)
        self.assertEqual(finding.unique_id_from_tool, "find-001")
        self.assertEqual(finding.vuln_id_from_tool, "AC-3")
        self.assertIn("arn:aws:s3:::test-bucket", finding.description)
        self.assertIn("Observation [obs-001]", finding.description)

    def test_oscal_passing_finding_mitigated(self):
        sample_oscal = {
            "assessment-results": {
                "results": [
                    {
                        "uuid": "res-pass",
                        "findings": [
                            {
                                "uuid": "find-pass-001",
                                "title": "IAM Root MFA Enabled",
                                "description": "Root account has MFA enabled",
                                "target": {
                                    "target-id": "arn:aws:iam::123456789012:root",
                                    "status": "pass",
                                },
                                "props": [
                                    {"name": "severity", "value": "low"},
                                    {"name": "control_id", "value": "IA-2"},
                                ],
                            }
                        ],
                    }
                ]
            }
        }

        findings = self.parser.get_findings(json.dumps(sample_oscal), self.test)
        self.assertEqual(len(findings), 1)
        finding = findings[0]

        self.assertFalse(finding.active)
        self.assertTrue(finding.is_mitigated)
        self.assertEqual(finding.severity, "Low")

    def test_oscal_empty_payload(self):
        findings = self.parser.get_findings("{}", self.test)
        self.assertEqual(len(findings), 0)

    def test_oscal_scan_types(self):
        scan_types = self.parser.get_scan_types()
        self.assertIn("NIST OSCAL Assessment Results", scan_types)


if __name__ == "__main__":
    unittest.main()
