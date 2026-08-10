import io
import json

from dojo.models import Test
from dojo.tools.cloudsplaining.parser import CloudsplainingParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestCloudsplainingParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("cloudsplaining") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = CloudsplainingParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("cloudsplaining") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = CloudsplainingParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("ResourceExposure: InsecurePolicy", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("ResourceExposure", finding.vuln_id_from_tool)
            self.assertEqual("InsecurePolicy", finding.component_name)
            self.assertIn("**Risk:** ResourceExposure", finding.description)
            self.assertIn("**Policy type:** customer_managed_policies", finding.description)
            self.assertIn("**Flagged actions (1):**", finding.description)
            self.assertIn("Restrict the policy", finding.mitigation)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_parse_many_findings(self):
        """One Finding per policy and risk category, not per flagged action."""
        with (get_unit_tests_scans_path("cloudsplaining") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = CloudsplainingParser().get_findings(testfile, Test())
            self.assertEqual(15, len(findings))

            with self.subTest("privilege escalation is the most severe category"):
                escalation = [f for f in findings if f.vuln_id_from_tool == "PrivilegeEscalation"]
                self.assertEqual(2, len(escalation))
                self.assertEqual({"Critical"}, {f.severity for f in escalation})

            with self.subTest("infrastructure modification is the noisiest and lowest"):
                modification = [f for f in findings if f.vuln_id_from_tool == "InfrastructureModification"]
                self.assertEqual(4, len(modification))
                self.assertEqual({"Low"}, {f.severity for f in modification})

            with self.subTest("a policy with many risks yields one finding per risk"):
                excessive = [f for f in findings if f.component_name == "ExcessivePermissions"]
                self.assertEqual(5, len(excessive))
                self.assertEqual(
                    {"PrivilegeEscalation", "DataExfiltration", "ResourceExposure",
                     "ServiceWildcard", "InfrastructureModification"},
                    {f.vuln_id_from_tool for f in excessive},
                )

            with self.subTest("the actions themselves reach the description"):
                exfiltration = next(
                    f for f in findings
                    if f.component_name == "OverprivilegedEC2" and f.vuln_id_from_tool == "DataExfiltration"
                )
                self.assertIn("**Flagged actions (2):**", exfiltration.description)
                self.assertIn("- ", exfiltration.description)

    def test_excluded_policies_are_skipped(self):
        """Cloudsplaining keeps excluded policies in the results, flagged rather than removed."""
        report = {
            "customer_managed_policies": {
                "kept": {"PolicyName": "Kept", "ResourceExposure": ["s3:PutBucketAcl"], "is_excluded": False},
                "skipped": {"PolicyName": "Skipped", "ResourceExposure": ["s3:PutBucketAcl"], "is_excluded": True},
            },
        }
        findings = CloudsplainingParser().get_findings(io.StringIO(json.dumps(report)), Test())
        self.assertEqual(1, len(findings))
        self.assertEqual("Kept", findings[0].component_name)
