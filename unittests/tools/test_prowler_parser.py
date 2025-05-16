from dojo.models import Test
from dojo.tools.prowler.parser import ProwlerParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestProwlerParser(DojoTestCase):
    def test_aws_csv_parser(self):
        """Test parsing AWS CSV report with 1 finding"""
        with (get_unit_tests_scans_path("prowler") / "aws.csv").open(encoding="utf-8") as test_file:
            parser = ProwlerParser()
            findings = parser.get_findings(test_file, Test())

            self.assertEqual(1, len(findings))

            finding = findings[0]
            self.assertEqual(
                "iam_root_hardware_mfa_enabled: Ensure hardware MFA is enabled for the root account", finding.title,
            )
            self.assertEqual("iam_root_hardware_mfa_enabled", finding.vuln_id_from_tool)
            self.assertEqual("High", finding.severity)
            self.assertTrue(finding.active)
            self.assertIn("AWS", finding.unsaved_tags)
            self.assertIn("iam", finding.unsaved_tags)

    def test_aws_json_parser(self):
        """Test parsing AWS JSON report with 1 finding"""
        with (get_unit_tests_scans_path("prowler") / "aws.json").open(encoding="utf-8") as test_file:
            parser = ProwlerParser()
            findings = parser.get_findings(test_file, Test())

            self.assertEqual(1, len(findings))

            finding = findings[0]
            self.assertEqual("Hardware MFA is not enabled for the root account.", finding.title)
            self.assertEqual("iam_root_hardware_mfa_enabled", finding.vuln_id_from_tool)
            self.assertEqual("High", finding.severity)
            self.assertTrue(finding.active)
            self.assertIn("aws", finding.unsaved_tags)

    def test_azure_csv_parser(self):
        """Test parsing Azure CSV report with 1 finding"""
        with (get_unit_tests_scans_path("prowler") / "azure.csv").open(encoding="utf-8") as test_file:
            parser = ProwlerParser()
            findings = parser.get_findings(test_file, Test())

            self.assertEqual(1, len(findings))

            finding = findings[0]
            self.assertEqual(
                "aks_network_policy_enabled: Ensure Network Policy is Enabled and set as appropriate", finding.title,
            )
            self.assertEqual("aks_network_policy_enabled", finding.vuln_id_from_tool)
            self.assertEqual("Medium", finding.severity)
            self.assertFalse(finding.active)  # PASS status
            self.assertIn("AZURE", finding.unsaved_tags)
            self.assertIn("aks", finding.unsaved_tags)

    def test_azure_json_parser(self):
        """Test parsing Azure JSON report with 1 finding"""
        with (get_unit_tests_scans_path("prowler") / "azure.json").open(encoding="utf-8") as test_file:
            parser = ProwlerParser()
            findings = parser.get_findings(test_file, Test())

            self.assertEqual(1, len(findings))

            finding = findings[0]
            self.assertEqual(
                "Network policy is enabled for cluster '<resource_name>' in subscription '<account_name>'.",
                finding.title,
            )
            self.assertEqual("aks_network_policy_enabled", finding.vuln_id_from_tool)
            self.assertEqual("Medium", finding.severity)
            self.assertFalse(finding.active)  # PASS status
            self.assertIn("azure", finding.unsaved_tags)

    def test_gcp_csv_parser(self):
        """Test parsing GCP CSV report with 1 finding"""
        with (get_unit_tests_scans_path("prowler") / "gcp.csv").open(encoding="utf-8") as test_file:
            parser = ProwlerParser()
            findings = parser.get_findings(test_file, Test())

            # Find the correct finding by checking the title
            gcp_findings = [f for f in findings if "rdp" in f.title.lower()]
            self.assertTrue(len(gcp_findings) >= 1, "No RDP-related findings found")

            finding = gcp_findings[0]
            self.assertEqual(
                "compute_firewall_rdp_access_from_the_internet_allowed: Ensure That RDP Access Is Restricted From the Internet",
                finding.title,
            )
            self.assertEqual("bc_gcp_networking_2", finding.vuln_id_from_tool)
            self.assertEqual("High", finding.severity)
            self.assertTrue(finding.active)
            self.assertIn("GCP", finding.unsaved_tags)
            self.assertIn("firewall", finding.unsaved_tags)

    def test_gcp_json_parser(self):
        """Test parsing GCP JSON report with 1 finding"""
        with (get_unit_tests_scans_path("prowler") / "gcp.json").open(encoding="utf-8") as test_file:
            parser = ProwlerParser()
            findings = parser.get_findings(test_file, Test())

            self.assertEqual(1, len(findings))

            finding = findings[0]
            self.assertEqual("Firewall rule default-allow-rdp allows 0.0.0.0/0 on port RDP.", finding.title)
            self.assertEqual("bc_gcp_networking_2", finding.vuln_id_from_tool)
            self.assertEqual("High", finding.severity)
            self.assertTrue(finding.active)
            self.assertIn("gcp", finding.unsaved_tags)

    def test_kubernetes_csv_parser(self):
        """Test parsing Kubernetes CSV report with 1 finding"""
        with (get_unit_tests_scans_path("prowler") / "kubernetes.csv").open(encoding="utf-8") as test_file:
            parser = ProwlerParser()
            findings = parser.get_findings(test_file, Test())

            self.assertEqual(1, len(findings))

            finding = findings[0]
            self.assertEqual(
                "bc_k8s_pod_security_1: Ensure that admission control plugin AlwaysPullImages is set", finding.title,
            )
            self.assertEqual("bc_k8s_pod_security_1", finding.vuln_id_from_tool)
            self.assertEqual("Medium", finding.severity)
            self.assertTrue(finding.active)
            self.assertIn("KUBERNETES", finding.unsaved_tags)
            self.assertIn("cluster-security", finding.unsaved_tags)

    def test_kubernetes_json_parser(self):
        """Test parsing Kubernetes JSON report with 2 findings"""
        with (get_unit_tests_scans_path("prowler") / "kubernetes.json").open(encoding="utf-8") as test_file:
            parser = ProwlerParser()
            findings = parser.get_findings(test_file, Test())

            self.assertEqual(2, len(findings))

            # Verify first finding (FAIL)
            finding1 = findings[0]
            self.assertEqual("AlwaysPullImages admission control plugin is not set in pod <pod>.", finding1.title)
            self.assertEqual("Medium", finding1.severity)
            self.assertTrue(finding1.active)

            # Verify second finding (PASS)
            finding2 = findings[1]
            self.assertEqual("API Server does not have anonymous-auth enabled in pod <pod>.", finding2.title)
            self.assertEqual("High", finding2.severity)
            self.assertFalse(finding2.active)  # PASS status
