from dojo.models import Test
from dojo.tools.pluto.parser import PlutoParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestPlutoParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("pluto") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = PlutoParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("pluto") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = PlutoParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Removed API extensions/v1beta1 used by Deployment/example-legacy", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("Deployment/example-legacy", finding.component_name)
            self.assertEqual("extensions/v1beta1", finding.component_version)
            self.assertEqual("extensions/v1beta1/Deployment", finding.vuln_id_from_tool)
            self.assertEqual("manifests/deprecated.yaml", finding.file_path)
            self.assertIn("**Removed in:** v1.16.0", finding.description)
            self.assertIn("**Replacement API:** apps/v1", finding.description)
            self.assertIn("**Namespace:** example-ns", finding.description)
            self.assertEqual(
                "Migrate Deployment/example-legacy from extensions/v1beta1 to apps/v1.",
                finding.mitigation,
            )
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("pluto") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = PlutoParser().get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

            with self.subTest("an already-removed API outranks one merely deprecated"):
                self.assertEqual(2, len([f for f in findings if f.severity == "High"]))
                deprecated = [f for f in findings if f.severity == "Medium"]
                self.assertEqual(1, len(deprecated))
                self.assertEqual("Ingress/example-ingress", deprecated[0].component_name)
                self.assertIn("**State:** deprecated", deprecated[0].description)

            with self.subTest("each object is keyed by its API version and kind"):
                self.assertEqual(
                    {"extensions/v1beta1/Deployment", "policy/v1beta1/PodDisruptionBudget",
                     "networking.k8s.io/v1beta1/Ingress"},
                    {f.vuln_id_from_tool for f in findings},
                )
