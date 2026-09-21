from dojo.models import Test
from dojo.tools.kube_score.parser import KubeScoreParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestKubeScoreParser(DojoTestCase):

    def test_parse_no_findings(self):
        """Passing (grade 10) and skipped checks must not produce Findings."""
        with (get_unit_tests_scans_path("kube_score") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = KubeScoreParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("kube_score") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = KubeScoreParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Container Ephemeral Storage Request and Limit", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("container-ephemeral-storage-request-and-limit", finding.vuln_id_from_tool)
            self.assertEqual("Deployment/apps/v1/example-ns/example-api", finding.component_name)
            self.assertEqual("manifests/deployment.yaml", finding.file_path)
            self.assertEqual(1, finding.line)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)
            self.assertIn("Ephemeral Storage limit is not set", finding.description)
            self.assertIn("Resource limits are recommended", finding.mitigation)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("kube_score") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = KubeScoreParser().get_findings(testfile, Test())
            self.assertEqual(8, len(findings))

            with self.subTest("grade 1 maps to High"):
                critical = [f for f in findings if f.severity == "High"]
                self.assertEqual(7, len(critical))
                self.assertIn(
                    "container-security-context-privileged",
                    [f.vuln_id_from_tool for f in critical],
                )

            with self.subTest("grade 5 maps to Medium"):
                warnings = [f for f in findings if f.severity == "Medium"]
                self.assertEqual(1, len(warnings))
                self.assertEqual("deployment-has-host-podantiaffinity", warnings[0].vuln_id_from_tool)
                self.assertIn("podAntiAffinity", warnings[0].description)

            with self.subTest("every finding carries its object and check id"):
                for finding in findings:
                    self.assertTrue(finding.title)
                    self.assertTrue(finding.vuln_id_from_tool)
                    self.assertEqual("Deployment/apps/v1/example-ns/example-api", finding.component_name)

    def test_parse_empty_report(self):
        """kube-score emits 'null' when it scores nothing at all."""
        with (get_unit_tests_scans_path("kube_score") / "empty.json").open(encoding="utf-8") as testfile:
            findings = KubeScoreParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))
