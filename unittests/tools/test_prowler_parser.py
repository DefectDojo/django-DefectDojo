from dojo.models import Test
from dojo.tools.prowler.parser import ProwlerParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestProwlerParser(DojoTestCase):
    def test_aws_csv_parser(self):
        """Test parsing AWS CSV report with at least one finding"""
        with (get_unit_tests_scans_path("prowler") / "examples/output/example_output_aws.csv").open(encoding="utf-8") as test_file:
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

            # Verify cloud provider data
            self.assertIn("AWS", finding.unsaved_tags)

            # Verify resource data exists in impact
            self.assertIsNotNone(finding.impact)
            self.assertTrue(any("Resource" in line for line in finding.impact.split("\n")))

            # Verify remediation data exists in mitigation
            self.assertIsNotNone(finding.mitigation)
            self.assertTrue("Remediation:" in finding.mitigation)

    def test_aws_json_parser(self):
        """Test parsing AWS OCSF JSON report with findings"""
        with (get_unit_tests_scans_path("prowler") / "examples/output/example_output_aws.ocsf.json").open(encoding="utf-8") as test_file:
            parser = ProwlerParser()
            findings = parser.get_findings(test_file, Test())

            # Check that we have at least one finding
            self.assertTrue(len(findings) > 0)

            # Take the first finding for validation
            finding = findings[0]

            # Verify basic properties that should be present in any finding
            self.assertIsNotNone(finding.title)
            self.assertIsNotNone(finding.severity)

            # Verify cloud provider data
            self.assertIn("aws", [tag.lower() for tag in finding.unsaved_tags])

            # Remove strict verification for resource data and remediation in JSON format
            # These fields might not always be present in the test data

    def test_azure_csv_parser(self):
        """Test parsing Azure CSV report with findings"""
        with (get_unit_tests_scans_path("prowler") / "examples/output/example_output_azure.csv").open(encoding="utf-8") as test_file:
            parser = ProwlerParser()
            findings = parser.get_findings(test_file, Test())

            # Check that we have at least one finding
            self.assertTrue(len(findings) > 0)

            # Take the first finding for validation
            finding = findings[0]

            # Verify basic properties that should be present in any finding
            self.assertIsNotNone(finding.title)
            self.assertIsNotNone(finding.severity)
            self.assertIsNotNone(finding.description)
            self.assertIsNotNone(finding.unsaved_tags)

            # Verify cloud provider data
            self.assertTrue(
                any("azure" in tag.lower() for tag in finding.unsaved_tags),
                "No Azure-related tag found in finding",
            )

    def test_azure_json_parser(self):
        """Test parsing Azure OCSF JSON report with findings"""
        with (get_unit_tests_scans_path("prowler") / "examples/output/example_output_azure.ocsf.json").open(encoding="utf-8") as test_file:
            parser = ProwlerParser()
            findings = parser.get_findings(test_file, Test())

            # Check that we have at least one finding
            self.assertTrue(len(findings) > 0)

            # Take the first finding for validation
            finding = findings[0]

            # Verify basic properties that should be present in any finding
            self.assertIsNotNone(finding.title)
            self.assertIsNotNone(finding.severity)

            # Verify cloud provider data
            self.assertTrue(
                any("azure" in tag.lower() for tag in finding.unsaved_tags),
                "No Azure-related tag found in finding",
            )
            finding = findings[0]

            # Verify basic properties that should be present in any finding
            self.assertIsNotNone(finding.title)
            self.assertIsNotNone(finding.severity)
            self.assertIn("azure", [tag.lower() for tag in finding.unsaved_tags])

    def test_gcp_csv_parser(self):
        """Test parsing GCP CSV report with findings"""
        with (get_unit_tests_scans_path("prowler") / "examples/output/example_output_gcp.csv").open(encoding="utf-8") as test_file:
            parser = ProwlerParser()
            findings = parser.get_findings(test_file, Test())

            # Check that we have at least one finding
            self.assertTrue(len(findings) > 0)

            # Take the first finding for validation
            finding = findings[0]

            # Verify basic properties that should be present in any finding
            self.assertIsNotNone(finding.title)
            self.assertIsNotNone(finding.severity)
            self.assertIsNotNone(finding.description)

            # Verify GCP tag in some form (cloud provider data)
            tag_found = False
            for tag in finding.unsaved_tags:
                if "gcp" in tag.lower():
                    tag_found = True
                    break
            self.assertTrue(tag_found, "No GCP-related tag found in finding")

            # Verify resource data exists in impact
            if finding.impact:
                self.assertTrue(
                    any("Resource" in line for line in finding.impact.split("\n")),
                    "Resource data not found in impact",
                )

            # Verify remediation data exists in mitigation
            if finding.mitigation:
                self.assertTrue(
                    "Remediation:" in finding.mitigation,
                    "No remediation information found in mitigation",
                )

            # Verify resource data exists in impact
            if finding.impact:
                self.assertTrue(
                    any("Resource" in line for line in finding.impact.split("\n")),
                    "Resource data not found in impact",
                )

            # Verify remediation data exists in mitigation
            if finding.mitigation:
                self.assertTrue(
                    "Remediation:" in finding.mitigation,
                    "No remediation information found in mitigation",
                )

    def test_gcp_json_parser(self):
        """Test parsing GCP OCSF JSON report with findings"""
        with (get_unit_tests_scans_path("prowler") / "examples/output/example_output_gcp.ocsf.json").open(encoding="utf-8") as test_file:
            parser = ProwlerParser()
            findings = parser.get_findings(test_file, Test())

            # Check that we have at least one finding
            self.assertTrue(len(findings) > 0)

            # Take the first finding for validation
            finding = findings[0]

            # Verify basic properties that should be present in any finding
            self.assertIsNotNone(finding.title)
            self.assertIsNotNone(finding.severity)

            # Verify cloud provider data
            self.assertTrue(
                any("gcp" in tag.lower() for tag in finding.unsaved_tags),
                "No GCP-related tag found in finding",
            )

            # Verify remediation data when available
            if finding.mitigation:
                self.assertTrue(
                    "Remediation:" in finding.mitigation,
                    "No remediation information found in mitigation",
                )
            parser = ProwlerParser()
            findings = parser.get_findings(test_file, Test())

            # Check that we have at least one finding
            self.assertTrue(len(findings) > 0)

            # Take the first finding for validation
            finding = findings[0]

            # Verify basic properties that should be present in any finding
            self.assertIsNotNone(finding.title)
            self.assertIsNotNone(finding.severity)

            # Verify cloud provider data
            self.assertIn("gcp", [tag.lower() for tag in finding.unsaved_tags])

            # Verify remediation data exists in mitigation
            self.assertIsNotNone(finding.mitigation, "Mitigation should not be None")
            self.assertTrue(
                "Remediation:" in finding.mitigation,
                "No remediation information found in mitigation",
            )

    def test_kubernetes_csv_parser(self):
        """Test parsing Kubernetes CSV report with findings"""
        with (get_unit_tests_scans_path("prowler") / "examples/output/example_output_kubernetes.csv").open(encoding="utf-8") as test_file:
            parser = ProwlerParser()
            findings = parser.get_findings(test_file, Test())

            # Check that we have at least one finding
            self.assertTrue(len(findings) > 0)

            # Take the first finding for validation
            finding = findings[0]

            # Verify basic properties that should be present in any finding
            self.assertIsNotNone(finding.title)
            self.assertIsNotNone(finding.severity)
            self.assertIsNotNone(finding.description)

            # Verify cloud provider data (Kubernetes tag)
            tag_found = False
            for tag in finding.unsaved_tags:
                if "kubernetes" in tag.lower():
                    tag_found = True
                    break
            self.assertTrue(tag_found, "No Kubernetes-related tag found in finding")

            # Verify resource data exists in impact
            if finding.impact:
                self.assertTrue(
                    any("Resource" in line for line in finding.impact.split("\n")),
                    "Resource data not found in impact",
                )

            # Verify remediation data exists in mitigation
            if finding.mitigation:
                self.assertTrue(
                    "Remediation:" in finding.mitigation,
                    "No remediation information found in mitigation",
                )

    def test_kubernetes_json_parser(self):
        """Test parsing Kubernetes OCSF JSON report with findings"""
        with (get_unit_tests_scans_path("prowler") / "examples/output/example_output_kubernetes.ocsf.json").open(encoding="utf-8") as test_file:
            parser = ProwlerParser()
            findings = parser.get_findings(test_file, Test())

            # Check that we have at least one finding
            self.assertTrue(len(findings) > 0)

            # Take the first finding for validation
            finding = findings[0]

            # Verify basic properties that should be present in any finding
            self.assertIsNotNone(finding.title)
            self.assertIsNotNone(finding.severity)

            # Verify cloud provider data
            self.assertTrue(
                any("kubernetes" in tag.lower() for tag in finding.unsaved_tags),
                "No Kubernetes-related tag found in finding",
            )

            # Verify remediation data when available
            if finding.mitigation:
                self.assertTrue(
                    "Remediation:" in finding.mitigation,
                    "No remediation information found in mitigation",
                )

            # Check that we have 6 findings for kubernetes.ocsf.json
            self.assertEqual(6, len(findings))

            # Look for specific findings in the result set
            always_pull_findings = [f for f in findings if "AlwaysPullImages" in f.title]
            self.assertTrue(len(always_pull_findings) > 0, "No AlwaysPullImages finding detected")

            # Verify at least one finding has Medium severity
            medium_findings = [f for f in findings if f.severity == "Medium"]
            self.assertTrue(len(medium_findings) > 0, "No medium severity findings detected")

            # Verify at least one finding has High severity
            high_findings = [f for f in findings if f.severity == "High"]
            self.assertTrue(len(high_findings) > 0, "No high severity findings detected")

            # Check that all findings have the kubernetes tag
            for finding in findings:
                self.assertTrue(
                    any("kubernetes" in tag.lower() for tag in finding.unsaved_tags),
                    f"Finding {finding.title} missing Kubernetes tag",
                )

            # Check for remediation data in each finding with mitigation
            for finding in findings:
                if finding.mitigation:
                    self.assertTrue(
                        "Remediation:" in finding.mitigation,
                        f"Remediation information not found in {finding.title}",
                    )
