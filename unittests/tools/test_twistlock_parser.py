

from dojo.models import Test
from dojo.tools.twistlock.parser import TwistlockParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestTwistlockParser(DojoTestCase):
    def test_parse_file_with_no_vuln(self):
        testfile = (get_unit_tests_scans_path("twistlock") / "no_vuln.json").open(encoding="utf-8")
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_and_compliance(self):
        testfile = (get_unit_tests_scans_path("twistlock") / "one_vuln.json").open(encoding="utf-8")
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        # Should have 2 findings: 1 vulnerability + 1 compliance
        self.assertEqual(2, len(findings))

        # Find the vulnerability and compliance findings
        for finding in findings:
            if finding.title.startswith("Compliance:"):
                # Verify compliance finding exists and has correct properties
                self.assertIsNotNone(finding)
                self.assertEqual("Compliance: (CIS_Kubernetes_v1.6.0 - 1.1) Ensure API server encryption is enabled", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertIn("Compliance ID", finding.description)
                self.assertIn("912", finding.description)
                self.assertIn("Category", finding.description)
                self.assertIn("Kubernetes", finding.description)
                self.assertIn("Encrypting etcd data at rest", finding.description)
                self.assertIn("Layer Time", finding.description)
                self.assertEqual("912", finding.vuln_id_from_tool)
                self.assertIn("compliance", finding.unsaved_tags)
                self.assertIn("kubernetes", finding.unsaved_tags)

                # Verify compliance finding has image metadata in impact field
                self.assertIn("Image ID:", finding.impact)
                self.assertIn("Distribution:", finding.impact)
                self.assertIn("\n", finding.impact)
            else:
                # Verify vulnerability finding exists and has correct properties
                self.assertIsNotNone(finding)
                self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
                self.assertEqual("CVE-2013-7459", finding.unsaved_vulnerability_ids[0])

                # Verify vulnerability finding has image metadata in impact field
                self.assertIn("Image ID:", finding.impact)
                self.assertIn("Distribution:", finding.impact)
                self.assertIn("Debian GNU/Linux 9", finding.impact)
                self.assertIn("\n", finding.impact)

    def test_parse_csv_with_timestamps_and_metadata(self):
        testfile = (
            get_unit_tests_scans_path("twistlock") / "scan_report_prisma_twistlock_images_four_vulns.csv").open(encoding="utf-8",
        )
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(4, len(findings))

        # Test first finding for timestamp and metadata
        finding = findings[0]

        # Verify timestamp parsing (Item 4)
        self.assertIsNotNone(finding.date)
        # Should use Published date (2020-09-04) or Discovered date (2020-09-29)
        self.assertEqual(finding.date.year, 2020)
        self.assertIn(finding.date.month, {9, 1, 11, 12})  # Various months from the test data

        # Verify metadata in impact field (Item 3) - now separated by newlines
        self.assertIn("Registry:", finding.impact)
        self.assertIn("111111111111.dkr.ecr.eu-central-1.amazonaws.com", finding.impact)
        self.assertIn("Repository:", finding.impact)
        self.assertIn("nginx-ingress-controller", finding.impact)
        self.assertIn("Tag:", finding.impact)
        self.assertIn("0.32.0", finding.impact)
        self.assertIn("Image ID:", finding.impact)
        self.assertIn("sha256:", finding.impact)
        self.assertIn("Distribution:", finding.impact)
        self.assertIn("alpine-3.11.5", finding.impact)
        self.assertIn("Hosts:", finding.impact)
        self.assertIn("76", finding.impact)
        self.assertIn("Containers:", finding.impact)
        self.assertIn("46", finding.impact)
        self.assertIn("Clusters:", finding.impact)
        self.assertIn("alpha", finding.impact)
        self.assertIn("Published:", finding.impact)
        self.assertIn("Discovered:", finding.impact)

        # Verify newline separation format
        self.assertTrue("\n" in finding.impact)

        # Verify vulnerability ID
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2020-24977", finding.unsaved_vulnerability_ids[0])

    def test_parse_file_with_no_link_no_description(self):
        testfile = (get_unit_tests_scans_path("twistlock") / "one_vuln_no_link_no_description.json").open(encoding="utf-8")
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        # Should have 2 findings: 1 vulnerability + 1 compliance
        self.assertEqual(2, len(findings))

        # Find the vulnerability finding (not compliance)
        for finding in findings:
            if not finding.title.startswith("Compliance:"):
                self.assertIsNotNone(finding)
                self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
                self.assertEqual("PRISMA-2021-0013", finding.unsaved_vulnerability_ids[0])
                self.assertEqual("2022-11-16", finding.date)
                break

    def test_parse_file_with_no_cvss(self):
        testfile = (get_unit_tests_scans_path("twistlock") / "no_cvss.json").open(encoding="utf-8")
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        # Should have 4 findings: 3 vulnerabilities + 1 compliance
        self.assertEqual(3, len(findings))

        for finding in findings:
            if finding.title.startswith("Compliance:"):
                # Verify compliance finding exists
                self.assertIn("CIS_Docker_v1.5.0 - 4.6", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertIn("404", finding.vuln_id_from_tool)
            else:
                # This should be a vulnerability finding
                self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
                finding.unsaved_vulnerability_ids[0]
                # Findings without CVSS should have None or empty CVSS fields
                self.assertIsNone(finding.cvssv3)
                self.assertIsNone(finding.cvssv3_score)

                # All vulnerability findings should have impact metadata
                self.assertIn("Image ID:", finding.impact)
                self.assertIn("Distribution:", finding.impact)
                self.assertIn("Debian GNU/Linux 12", finding.impact)
                self.assertEqual("2025-07-08", finding.date)

    def test_parse_file_with_many_vulns(self):
        testfile = (get_unit_tests_scans_path("twistlock") / "many_vulns.json").open(encoding="utf-8")
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        # Should have 6 findings: 5 vulnerabilities + 1 compliance
        self.assertEqual(6, len(findings))

    def test_parse_file_which_contain_packages_info(self):
        testfile = (get_unit_tests_scans_path("twistlock") / "findings_include_packages.json").open(encoding="utf-8")
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        # Should have 6 findings: 4 vulnerabilities + 2 compliance
        self.assertEqual(6, len(findings))

    def test_parse_file_prisma_twistlock_images_no_vuln(self):
        testfile = (
            get_unit_tests_scans_path("twistlock") / "scan_report_prisma_twistlock_images_no_vuln.csv").open(encoding="utf-8",
        )
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parse_file_prisma_twistlock_images_four_vulns(self):
        testfile = (
            get_unit_tests_scans_path("twistlock") / "scan_report_prisma_twistlock_images_four_vulns.csv").open(encoding="utf-8",
        )
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(4, len(findings))
        self.assertEqual(1, len(findings[0].unsaved_vulnerability_ids))
        self.assertEqual("CVE-2020-24977", findings[0].unsaved_vulnerability_ids[0])

    def test_parse_file_prisma_twistlock_images_long_package_name(self):
        testfile = (
            get_unit_tests_scans_path("twistlock") / "scan_report_prisma_twistlock_images_long_package_name.csv"
        ).open(encoding="utf-8")
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
