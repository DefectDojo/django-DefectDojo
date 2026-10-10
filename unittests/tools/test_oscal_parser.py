from django.test import TestCase

from dojo.models import Test
from dojo.tools.oscal.parser import OscalParser
from unittests.dojo_test_case import get_unit_tests_scans_path


class TestOscalParser(TestCase):
    def test_oscal_assessment_results_parsing(self):
        with (get_unit_tests_scans_path("oscal") / "single_failing_finding.json").open(encoding="utf-8") as testfile:
            parser = OscalParser()
            findings = parser.get_findings(testfile, Test())

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
        with (get_unit_tests_scans_path("oscal") / "passing_finding_mitigated.json").open(encoding="utf-8") as testfile:
            parser = OscalParser()
            findings = parser.get_findings(testfile, Test())

        self.assertEqual(len(findings), 1)
        finding = findings[0]

        self.assertFalse(finding.active)
        self.assertTrue(finding.is_mitigated)
        self.assertEqual(finding.severity, "Low")

    def test_oscal_empty_payload(self):
        with (get_unit_tests_scans_path("oscal") / "empty_payload.json").open(encoding="utf-8") as testfile:
            parser = OscalParser()
            findings = parser.get_findings(testfile, Test())
        self.assertEqual(len(findings), 0)

    def test_oscal_scan_types(self):
        parser = OscalParser()
        scan_types = parser.get_scan_types()
        self.assertIn("NIST OSCAL Assessment Results", scan_types)

    # ---- Regression: the OSCAL 1.2.3 schema defines finding.target.status
    # as a required *object* ({"state": ..., "reason": ...}), not a plain
    # string. A real, schema-valid document (e.g. from a fixed OSCAL
    # exporter) previously crashed this parser with
    # AttributeError: 'dict' object has no attribute 'lower', because
    # target_status.lower() assumed a string. Both shapes must work.

    def test_oscal_object_shaped_status_not_satisfied_is_active(self):
        path = get_unit_tests_scans_path("oscal") / "object_shaped_status_not_satisfied.json"
        with path.open(encoding="utf-8") as testfile:
            parser = OscalParser()
            findings = parser.get_findings(testfile, Test())

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertTrue(finding.active)
        self.assertFalse(finding.is_mitigated)

    def test_oscal_object_shaped_status_satisfied_is_mitigated(self):
        path = get_unit_tests_scans_path("oscal") / "object_shaped_status_satisfied.json"
        with path.open(encoding="utf-8") as testfile:
            parser = OscalParser()
            findings = parser.get_findings(testfile, Test())

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertFalse(finding.active)
        self.assertTrue(finding.is_mitigated)

    def test_oscal_missing_target_status_falls_back_to_props(self):
        path = get_unit_tests_scans_path("oscal") / "missing_target_status.json"
        with path.open(encoding="utf-8") as testfile:
            parser = OscalParser()
            findings = parser.get_findings(testfile, Test())

        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].active)
