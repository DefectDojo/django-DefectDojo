"""Unit tests for the Qualys VMDR parser."""

from dojo.tools.qualys_vmdr.parser import QualysVMDRParser

from dojo.models import Test
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestQualysVMDRParser(DojoTestCase):

    """Test cases for QualysVMDRParser."""

    def test_get_scan_types(self):
        """Test that parser returns correct scan type."""
        parser = QualysVMDRParser()
        self.assertEqual(["Qualys VMDR"], parser.get_scan_types())

    def test_get_label_for_scan_types(self):
        """Test that parser returns correct label."""
        parser = QualysVMDRParser()
        self.assertEqual("Qualys VMDR", parser.get_label_for_scan_types("Qualys VMDR"))

    def test_get_description_for_scan_types(self):
        """Test that parser returns a description."""
        parser = QualysVMDRParser()
        description = parser.get_description_for_scan_types("Qualys VMDR")
        self.assertIn("Qualys VMDR", description)

    def test_parse_qid_no_findings(self):
        """Test parsing QID format with no vulnerabilities."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "no_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_cve_no_findings(self):
        """Test parsing CVE format with no vulnerabilities."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "no_vuln_cve.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_qid_one_finding(self):
        """Test parsing QID format with single vulnerability."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_cve_one_finding(self):
        """Test parsing CVE format with single vulnerability."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_cve.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_qid_many_findings(self):
        """Test parsing QID format with multiple vulnerabilities."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "many_vulns_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(5, len(findings))

    def test_parse_cve_many_findings(self):
        """Test parsing CVE format with multiple vulnerabilities."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "many_vulns_cve.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(5, len(findings))
