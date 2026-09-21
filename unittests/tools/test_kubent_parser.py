from dojo.models import Test
from dojo.tools.kubent.parser import KubentParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestKubentParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("kubent") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = KubentParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("kubent") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = KubentParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Deprecated API extensions/v1beta1 used by Deployment/example-legacy", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("Deployment/example-legacy", finding.component_name)
            self.assertEqual("extensions/v1beta1", finding.component_version)
            self.assertEqual("extensions/v1beta1/Deployment", finding.vuln_id_from_tool)
            self.assertIn("**Namespace:** example-ns", finding.description)
            self.assertIn("**Replacement API:** apps/v1", finding.description)
            self.assertIn("**Deprecated since:** 1.9.0", finding.description)
            self.assertEqual(
                "Migrate Deployment/example-legacy from extensions/v1beta1 to apps/v1.",
                finding.mitigation,
            )
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_removal_release_is_parsed_from_the_ruleset_name(self):
        """Kubent only states the removal release in prose, as its ruleset name."""
        with (get_unit_tests_scans_path("kubent") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = KubentParser().get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
            by_kind = {f.component_name: f for f in findings}
            self.assertIn("**Removed in Kubernetes:** 1.16", by_kind["Deployment/example-legacy"].description)
            self.assertIn("**Removed in Kubernetes:** 1.25", by_kind["PodDisruptionBudget/example-pdb"].description)
            self.assertIn("**Removed in Kubernetes:** 1.22", by_kind["Ingress/example-ingress"].description)

    def test_every_reported_object_is_a_finding(self):
        """Kubent reports only deprecated usages, and grades none of them."""
        with (get_unit_tests_scans_path("kubent") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = KubentParser().get_findings(testfile, Test())
            self.assertEqual({"Medium"}, {f.severity for f in findings})
            self.assertEqual(3, len({f.vuln_id_from_tool for f in findings}))

    def test_ruleset_without_a_release_is_tolerated(self):
        parser = KubentParser()
        self.assertEqual("1.16", parser._removed_in("Deprecated APIs removed in 1.16"))
        self.assertIsNone(parser._removed_in("Custom ruleset"))
        self.assertIsNone(parser._removed_in(None))
