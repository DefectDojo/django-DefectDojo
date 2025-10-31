from dojo.models import Test
from dojo.tools.openreports.parser import OpenreportsParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


def sample_path(file_name):
    return get_unit_tests_scans_path("openreports") / file_name


class TestOpenreportsParser(DojoTestCase):
    def test_no_results(self):
        with sample_path("openreports_no_results.json").open(encoding="utf-8") as test_file:
            parser = OpenreportsParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 0)

    def test_single_report(self):
        with sample_path("openreports_single_report.json").open(encoding="utf-8") as test_file:
            parser = OpenreportsParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 3)

            # Test first finding (warn/low severity)
            finding1 = findings[0]
            self.assertEqual("CVE-2025-9232 in libcrypto3", finding1.title)
            self.assertEqual("Low", finding1.severity)
            self.assertEqual("libcrypto3", finding1.component_name)
            self.assertEqual("3.5.2-r1", finding1.component_version)
            self.assertEqual("Upgrade to version: 3.5.4-r0", finding1.mitigation)
            self.assertEqual("https://avd.aquasec.com/nvd/cve-2025-9232", finding1.references)
            self.assertEqual("test/Deployment/test-app", finding1.service)
            self.assertTrue(finding1.active)
            self.assertTrue(finding1.verified)
            self.assertTrue(finding1.fix_available)
            self.assertEqual(1, len(finding1.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2025-9232", finding1.unsaved_vulnerability_ids[0])
            self.assertEqual(
                "b1fcca57-2efd-44d3-89e9-949e29b61936:CVE-2025-9232:libcrypto3", finding1.unique_id_from_tool
            )
            self.assertIn("vulnerability scan", finding1.tags)
            self.assertIn("image-scanner", finding1.tags)
            self.assertIn("Deployment", finding1.tags)

            # Test second finding (fail/high severity)
            finding2 = findings[1]
            self.assertEqual("CVE-2025-47907 in stdlib", finding2.title)
            self.assertEqual("High", finding2.severity)
            self.assertEqual("stdlib", finding2.component_name)
            self.assertEqual("v1.24.4", finding2.component_version)
            self.assertEqual("Upgrade to version: 1.23.12, 1.24.6", finding2.mitigation)
            self.assertEqual("https://avd.aquasec.com/nvd/cve-2025-47907", finding2.references)
            self.assertEqual("test/Deployment/test-app", finding2.service)
            self.assertTrue(finding2.active)
            self.assertTrue(finding2.verified)
            self.assertTrue(finding2.fix_available)
            self.assertEqual(1, len(finding2.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2025-47907", finding2.unsaved_vulnerability_ids[0])
            self.assertEqual("b1fcca57-2efd-44d3-89e9-949e29b61936:CVE-2025-47907:stdlib", finding2.unique_id_from_tool)

            # Test third finding (non-CVE policy, fail/low severity)
            finding3 = findings[2]
            self.assertEqual("CIS-BENCH-001: Missing security headers in HTTP response", finding3.title)
            self.assertEqual("Low", finding3.severity)
            self.assertEqual("web-server", finding3.component_name)
            self.assertEqual("N/A", finding3.component_version)
            self.assertEqual("Upgrade to version: Configure proper security headers", finding3.mitigation)
            self.assertEqual("https://www.cisecurity.org/benchmark/docker", finding3.references)
            self.assertEqual("test/Deployment/test-app", finding3.service)
            self.assertTrue(finding3.active)
            self.assertTrue(finding3.verified)
            self.assertTrue(finding3.fix_available)
            # Non-CVE policies should not have vulnerability IDs
            self.assertIsNone(finding3.unsaved_vulnerability_ids)
            self.assertEqual(
                "b1fcca57-2efd-44d3-89e9-949e29b61936:CIS-BENCH-001:web-server", finding3.unique_id_from_tool
            )
            self.assertIn("compliance check", finding3.tags)
            self.assertIn("compliance-scanner", finding3.tags)
            self.assertIn("Deployment", finding3.tags)

    def test_list_format(self):
        with sample_path("openreports_list_format.json").open(encoding="utf-8") as test_file:
            parser = OpenreportsParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 3)

            # Verify findings from different reports have different services
            services = {finding.service for finding in findings}
            self.assertEqual(len(services), 2)
            self.assertIn("test/Deployment/app1", services)
            self.assertIn("test/Deployment/app2", services)

            # Verify CVE IDs - only findings with CVE policies should have vulnerability IDs
            cve_findings = [finding for finding in findings if finding.unsaved_vulnerability_ids]
            self.assertEqual(len(cve_findings), 2)
            cve_ids = [finding.unsaved_vulnerability_ids[0] for finding in cve_findings]
            self.assertIn("CVE-2025-9232", cve_ids)
            self.assertIn("CVE-2025-47907", cve_ids)

            # Verify there's at least one non-CVE finding
            non_cve_findings = [finding for finding in findings if not finding.unsaved_vulnerability_ids]
            self.assertEqual(len(non_cve_findings), 1)
            non_cve_finding = non_cve_findings[0]
            self.assertEqual("SECURITY-001: Container running as root user", non_cve_finding.title)

    def test_parser_metadata(self):
        parser = OpenreportsParser()
        scan_types = parser.get_scan_types()
        self.assertEqual(["OpenReports"], scan_types)

        label = parser.get_label_for_scan_types("OpenReports")
        self.assertEqual("OpenReports", label)

        description = parser.get_description_for_scan_types("OpenReports")
        self.assertEqual("Import OpenReports JSON report.", description)
