from dojo.models import Test
from dojo.tools.qualys_vmdr.parser import QualysVMDRParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestQualysVMDRParser(DojoTestCase):

    def test_get_scan_types(self):
        parser = QualysVMDRParser()
        self.assertEqual(["Qualys VMDR"], parser.get_scan_types())

    def test_get_label_for_scan_types(self):
        parser = QualysVMDRParser()
        self.assertEqual("Qualys VMDR", parser.get_label_for_scan_types("Qualys VMDR"))

    def test_get_description_for_scan_types(self):
        parser = QualysVMDRParser()
        description = parser.get_description_for_scan_types("Qualys VMDR")
        self.assertIn("Qualys VMDR", description)

    def test_parse_qid_no_findings(self):
        with (get_unit_tests_scans_path("qualys_vmdr") / "no_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_cve_no_findings(self):
        with (get_unit_tests_scans_path("qualys_vmdr") / "no_vuln_cve.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_qid_one_finding(self):
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_cve_one_finding(self):
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_cve.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_qid_many_findings(self):
        with (get_unit_tests_scans_path("qualys_vmdr") / "many_vulns_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(5, len(findings))

    def test_parse_cve_many_findings(self):
        with (get_unit_tests_scans_path("qualys_vmdr") / "many_vulns_cve.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(5, len(findings))

    def test_qid_severity_mapping_critical(self):
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("Critical", findings[0].severity)

    def test_qid_severity_justification(self):
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("Qualys Severity: 5", findings[0].severity_justification)

    def test_qid_unique_id_from_tool(self):
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("100269", findings[0].unique_id_from_tool)

    def test_qid_vuln_id_from_tool(self):
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("100269", findings[0].vuln_id_from_tool)

    def test_qid_active_status(self):
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertTrue(findings[0].active)

    def test_qid_fixed_status(self):
        with (get_unit_tests_scans_path("qualys_vmdr") / "many_vulns_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            fixed_finding = [f for f in findings if f.unique_id_from_tool == "100003"][0]
            self.assertFalse(fixed_finding.active)

    def test_qid_component_name(self):
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("TESTSERVER01", findings[0].component_name)

    def test_qid_service(self):
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("Internet Explorer", findings[0].service)

    def test_qid_endpoints_single_ip(self):
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            endpoints = self.get_unsaved_locations(findings[0])
            self.assertEqual(1, len(endpoints))
            self.assertEqual("10.0.0.1", endpoints[0].host)

    def test_qid_endpoints_multiple_ips(self):
        with (get_unit_tests_scans_path("qualys_vmdr") / "many_vulns_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            multi_ip_finding = [f for f in findings if f.unique_id_from_tool == "100003"][0]
            endpoints = self.get_unsaved_locations(multi_ip_finding)
            self.assertEqual(2, len(endpoints))
            hosts = [e.host for e in endpoints]
            self.assertIn("10.0.0.20", hosts)
            self.assertIn("10.0.0.21", hosts)

    def test_qid_endpoints_ipv6_fallback(self):
        with (get_unit_tests_scans_path("qualys_vmdr") / "many_vulns_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            ipv6_finding = [f for f in findings if f.unique_id_from_tool == "100005"][0]
            endpoints = self.get_unsaved_locations(ipv6_finding)
            self.assertEqual(1, len(endpoints))
            self.assertEqual("2001:db8::1", endpoints[0].host)

    def test_qid_tags(self):
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            tags = findings[0].unsaved_tags
            self.assertIn("Server", tags)
            self.assertIn("Production", tags)

    def test_qid_static_dynamic_flags(self):
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertTrue(findings[0].static_finding)
            self.assertFalse(findings[0].dynamic_finding)

    def test_qid_severity_mapping_all_levels(self):
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
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_cve.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("CVE-2021-44228", findings[0].vuln_id_from_tool)

    def test_cve_unique_id_from_tool(self):
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_cve.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("730143", findings[0].unique_id_from_tool)

    def test_cve_cvssv3_score(self):
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_cve.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(10.0, findings[0].cvssv3_score)

    def test_cve_description_includes_cve_info(self):
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_cve.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            description = findings[0].description
            self.assertIn("CVE-2021-44228", description)
            self.assertIn("Log4j", description)

    def test_qid_description_excludes_title_and_threat(self):
        """Title and Threat have dedicated fields; they should not be in description."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            description = findings[0].description
            self.assertNotIn("**Title:**", description)
            self.assertNotIn("**Threat:**", description)
            self.assertIn("**QID:**", description)

    def test_html_stripped_from_impact(self):
        """HTML tags like <P> should be stripped from the impact field."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertNotIn("<P>", findings[0].impact)
            self.assertIn("vulnerability", findings[0].impact)

    def test_no_metadata_cve_no_findings(self):
        """Test CVE format without metadata lines (header at line 1) with no data."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "no_vuln_no_metadata_cve.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_no_metadata_cve_one_finding(self):
        """Test CVE format without metadata lines (header at line 1) with data."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_no_metadata_cve.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            self.assertEqual("CVE-2021-44228", findings[0].vuln_id_from_tool)
            self.assertEqual("730143", findings[0].unique_id_from_tool)

    def test_no_metadata_html_stripped(self):
        """Test HTML stripping works in no-metadata variant too."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_no_metadata_cve.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertNotIn("<P>", findings[0].impact)

    def test_qid_endpoint_clean(self):
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8",
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.validate_locations(findings)
