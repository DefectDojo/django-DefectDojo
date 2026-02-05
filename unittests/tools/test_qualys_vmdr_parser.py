"""Unit tests for the Qualys VMDR parser."""

from dojo.models import Test
from dojo.tools.qualys_vmdr.parser import QualysVMDRParser
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

    def test_qid_severity_mapping_critical(self):
        """Test severity 5 maps to Critical."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("Critical", findings[0].severity)

    def test_qid_severity_justification(self):
        """Test severity justification preserves original score."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("Qualys Severity: 5", findings[0].severity_justification)

    def test_qid_unique_id_from_tool(self):
        """Test QID is mapped to unique_id_from_tool."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("100269", findings[0].unique_id_from_tool)

    def test_qid_active_status(self):
        """Test ACTIVE status maps to active=True."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertTrue(findings[0].active)

    def test_qid_fixed_status(self):
        """Test FIXED status maps to active=False."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "many_vulns_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            fixed_finding = [f for f in findings if f.unique_id_from_tool == "100003"][0]
            self.assertFalse(fixed_finding.active)

    def test_qid_component_name(self):
        """Test Asset Name maps to component_name."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("TESTSERVER01", findings[0].component_name)

    def test_qid_service(self):
        """Test Category maps to service."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("Internet Explorer", findings[0].service)

    def test_qid_endpoints_single_ip(self):
        """Test single IP creates one endpoint."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            endpoints = findings[0].unsaved_endpoints
            self.assertEqual(1, len(endpoints))
            self.assertEqual("10.0.0.1", endpoints[0].host)

    def test_qid_endpoints_multiple_ips(self):
        """Test comma-separated IPs create multiple endpoints."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "many_vulns_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            multi_ip_finding = [f for f in findings if f.unique_id_from_tool == "100003"][0]
            endpoints = multi_ip_finding.unsaved_endpoints
            self.assertEqual(2, len(endpoints))
            hosts = [e.host for e in endpoints]
            self.assertIn("10.0.0.20", hosts)
            self.assertIn("10.0.0.21", hosts)

    def test_qid_endpoints_ipv6_fallback(self):
        """Test IPv6 is used when IPv4 is empty."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "many_vulns_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            ipv6_finding = [f for f in findings if f.unique_id_from_tool == "100005"][0]
            endpoints = ipv6_finding.unsaved_endpoints
            self.assertEqual(1, len(endpoints))
            self.assertEqual("2001:db8::1", endpoints[0].host)

    def test_qid_tags(self):
        """Test Asset Tags are parsed into unsaved_tags."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            tags = findings[0].unsaved_tags
            self.assertIn("Server", tags)
            self.assertIn("Production", tags)

    def test_qid_static_dynamic_flags(self):
        """Test static_finding=True and dynamic_finding=False."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertTrue(findings[0].static_finding)
            self.assertFalse(findings[0].dynamic_finding)

    def test_qid_severity_mapping_all_levels(self):
        """Test all severity levels are correctly mapped."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "many_vulns_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            severity_map = {f.unique_id_from_tool: f.severity for f in findings}
            self.assertEqual("Info", severity_map["100001"])
            self.assertEqual("Low", severity_map["100002"])
            self.assertEqual("Medium", severity_map["100003"])
            self.assertEqual("High", severity_map["100004"])
            self.assertEqual("Critical", severity_map["100005"])

    def test_cve_vuln_id_from_tool(self):
        """Test CVE is mapped to vuln_id_from_tool."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_cve.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("CVE-2021-44228", findings[0].vuln_id_from_tool)

    def test_cve_unique_id_from_tool(self):
        """Test QID is still mapped to unique_id_from_tool in CVE format."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_cve.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("730143", findings[0].unique_id_from_tool)

    def test_cve_cvssv3_score(self):
        """Test CVSSv3.1 Base score is parsed."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_cve.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(10.0, findings[0].cvssv3_score)

    def test_cve_description_includes_cve_info(self):
        """Test CVE format description includes CVE details."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_cve.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            description = findings[0].description
            self.assertIn("CVE-2021-44228", description)
            self.assertIn("Log4j", description)
