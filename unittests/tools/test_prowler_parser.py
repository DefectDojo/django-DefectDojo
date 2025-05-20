from dojo.models import Test
from dojo.tools.prowler.parser import ProwlerParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestProwlerParser(DojoTestCase):
    def test_aws_csv_parser(self):
        """Test parsing AWS CSV report with at least one finding"""
        with (get_unit_tests_scans_path("prowler") / "aws.csv").open(encoding="utf-8") as test_file:
            parser = ProwlerParser()
            findings = parser.get_findings(test_file, Test())

            # Check that we have at least one finding
            self.assertTrue(len(findings) > 0)

            # Find the specific finding we want to test
            iam_findings = [
                f
                for f in findings
                if "iam" in f.title.lower() or (f.vuln_id_from_tool and "iam" in f.vuln_id_from_tool.lower())
            ]
            finding = iam_findings[0] if iam_findings else findings[0]

            # Verify basic properties that should be present in any finding
            self.assertIsNotNone(finding.title)
            self.assertIsNotNone(finding.severity)
            self.assertIsNotNone(finding.description)
            self.assertIsNotNone(finding.unsaved_tags)

    def test_aws_json_parser(self):
        """Test parsing AWS JSON report with findings"""
        with (get_unit_tests_scans_path("prowler") / "aws.json").open(encoding="utf-8") as test_file:
            parser = ProwlerParser()
            findings = parser.get_findings(test_file, Test())

            # Check that we have at least one finding
            self.assertTrue(len(findings) > 0)

            # Take the first finding for validation
            finding = findings[0]

            # Verify basic properties that should be present in any finding
            self.assertIsNotNone(finding.title)
            self.assertIsNotNone(finding.severity)
            self.assertIn("aws", [tag.lower() for tag in finding.unsaved_tags])

    def test_azure_csv_parser(self):
        """Test parsing Azure CSV report with 1 finding"""
        with (get_unit_tests_scans_path("prowler") / "azure.csv").open(encoding="utf-8") as test_file:
            parser = ProwlerParser()
            findings = parser.get_findings(test_file, Test())

            self.assertEqual(1, len(findings))

            finding = findings[0]
            self.assertEqual(
                "aks_network_policy_enabled: Ensure Network Policy is Enabled and set as appropriate",
                finding.title,
            )
            self.assertEqual("aks_network_policy_enabled", finding.vuln_id_from_tool)
            self.assertEqual("Medium", finding.severity)
            self.assertFalse(finding.active)  # PASS status
            self.assertIn("AZURE", finding.unsaved_tags)
            self.assertIn("aks", finding.unsaved_tags)

    def test_azure_json_parser(self):
        """Test parsing Azure JSON report with findings"""
        with (get_unit_tests_scans_path("prowler") / "azure.json").open(encoding="utf-8") as test_file:
            parser = ProwlerParser()
            findings = parser.get_findings(test_file, Test())

            # Check that we have at least one finding
            self.assertTrue(len(findings) > 0)

            # Take the first finding for validation
            finding = findings[0]

            # Verify basic properties that should be present in any finding
            self.assertIsNotNone(finding.title)
            self.assertIsNotNone(finding.severity)
            self.assertIn("azure", [tag.lower() for tag in finding.unsaved_tags])

    def test_gcp_csv_parser(self):
        """Test parsing GCP CSV report with findings"""
        with (get_unit_tests_scans_path("prowler") / "gcp.csv").open(encoding="utf-8") as test_file:
            parser = ProwlerParser()
            findings = parser.get_findings(test_file, Test())

            # Check that we have at least one finding
            self.assertTrue(len(findings) > 0)

            # Take the first finding for validation
            finding = findings[0]

            # Verify basic properties that should be present in any finding
            self.assertIsNotNone(finding.title)
            self.assertIsNotNone(finding.severity)
            # Verify GCP tag in some form
            tag_found = False
            for tag in finding.unsaved_tags:
                if "gcp" in tag.lower():
                    tag_found = True
                    break
            self.assertTrue(tag_found, "No GCP-related tag found in finding")

    def test_gcp_json_parser(self):
        """Test parsing GCP JSON report with findings"""
        with (get_unit_tests_scans_path("prowler") / "gcp.json").open(encoding="utf-8") as test_file:
            parser = ProwlerParser()
            findings = parser.get_findings(test_file, Test())

            # Check that we have at least one finding
            self.assertTrue(len(findings) > 0)

            # Take the first finding for validation
            finding = findings[0]

            # Verify basic properties that should be present in any finding
            self.assertIsNotNone(finding.title)
            self.assertIsNotNone(finding.severity)
            self.assertIn("gcp", [tag.lower() for tag in finding.unsaved_tags])

    def test_kubernetes_csv_parser(self):
        """Test parsing Kubernetes CSV report with findings"""
        with (get_unit_tests_scans_path("prowler") / "kubernetes.csv").open(encoding="utf-8") as test_file:
            parser = ProwlerParser()
            findings = parser.get_findings(test_file, Test())

            # Check that we have at least one finding
            self.assertTrue(len(findings) > 0)

            # Take the first finding for validation
            finding = findings[0]

            # Verify basic properties that should be present in any finding
            self.assertIsNotNone(finding.title)
            self.assertIsNotNone(finding.severity)
            # Verify Kubernetes tag in some form
            tag_found = False
            for tag in finding.unsaved_tags:
                if "kubernetes" in tag.lower():
                    tag_found = True
                    break
            self.assertTrue(tag_found, "No Kubernetes-related tag found in finding")

    def test_kubernetes_json_parser(self):
        """Test parsing Kubernetes JSON report with findings"""
        with (get_unit_tests_scans_path("prowler") / "kubernetes.json").open(encoding="utf-8") as test_file:
            parser = ProwlerParser()
            findings = parser.get_findings(test_file, Test())

            # Check that we have at least one finding
            self.assertTrue(len(findings) > 0)

            # Check active and inactive findings if multiple findings exist
            if len(findings) > 1:
                # Check that we have at least one active finding
                active_findings = [f for f in findings if f.active]

                # Verify we have active findings
                self.assertTrue(len(active_findings) > 0, "No active findings detected")

                # Verify basic properties for active findings
                finding = active_findings[0]
                self.assertIsNotNone(finding.title)
                self.assertIsNotNone(finding.severity)
            else:
                # Just verify the basic properties if only one finding
                finding = findings[0]
                self.assertIsNotNone(finding.title)
                self.assertIsNotNone(finding.severity)
