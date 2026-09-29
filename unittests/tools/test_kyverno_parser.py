import io
import json

from dojo.models import Test
from dojo.tools.kyverno.parser import KyvernoParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestKyvernoParser(DojoTestCase):

    def test_parse_no_findings(self):
        """The report holds two passing results, and a pass is not a finding."""
        with (get_unit_tests_scans_path("kyverno") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = KyvernoParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("kyverno") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = KyvernoParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual(
                "require-pod-hardening/require-run-as-non-root: Pod/sample-ns/sample-app",
                finding.title,
            )
            self.assertEqual("require-pod-hardening/require-run-as-non-root", finding.vuln_id_from_tool)
            self.assertEqual("Pod/sample-ns/sample-app", finding.component_name)
            self.assertIn("Containers must set runAsNonRoot to true.", finding.description)
            self.assertIn("**Result:** fail", finding.description)
            self.assertIn("**Category:** Pod Security", finding.description)

            with self.subTest("severity comes from the policy's own severity annotation"):
                self.assertEqual("High", finding.severity)
                self.assertIn("**Policy severity:** high", finding.description)

    def test_parse_many_findings(self):
        """The report mixes passes and failures; only the failures are imported."""
        with (get_unit_tests_scans_path("kyverno") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = KyvernoParser().get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
            self.assertEqual({"High"}, {f.severity for f in findings})
            self.assertEqual(
                {"require-pod-hardening/require-run-as-non-root", "require-pod-hardening/require-resource-limits"},
                {f.vuln_id_from_tool for f in findings},
            )
            self.assertEqual({"Pod/sample-ns/sample-app"}, {f.component_name for f in findings})

    def test_severity_falls_back_to_the_result_when_the_policy_declares_none(self):
        parser = KyvernoParser()
        self.assertEqual("Medium", parser._severity("", "fail"))
        self.assertEqual("Low", parser._severity("", "warn"))
        self.assertEqual("High", parser._severity("", "error"))
        self.assertEqual("Critical", parser._severity("critical", "fail"))
        self.assertEqual("Info", parser._severity("info", "fail"))

        with self.subTest("an unknown declared severity does not win over a sane default"):
            self.assertEqual("Medium", parser._severity("bogus", "fail"))

    def test_classic_policyreport_and_lists_are_accepted(self):
        """Kyverno emits openreports.io now, but wgpolicyk8s.io PolicyReports are still in use."""
        payload = {
            "apiVersion": "v1",
            "kind": "List",
            "items": [
                {
                    "apiVersion": "wgpolicyk8s.io/v1alpha2",
                    "kind": "PolicyReport",
                    "metadata": {"name": "polr-ns-sample", "namespace": "sample-ns"},
                    "summary": {"pass": 0, "fail": 1, "warn": 0, "error": 0, "skip": 0},
                    "results": [
                        {
                            "policy": "disallow-latest-tag",
                            "rule": "require-image-tag",
                            "result": "fail",
                            "severity": "medium",
                            "message": "An image tag is required.",
                            "resources": [
                                {"kind": "Deployment", "namespace": "sample-ns", "name": "sample-api",
                                 "apiVersion": "apps/v1"},
                            ],
                        },
                        {"policy": "disallow-latest-tag", "rule": "require-image-tag", "result": "skip"},
                    ],
                },
            ],
        }
        findings = KyvernoParser().get_findings(io.StringIO(json.dumps(payload)), Test())
        self.assertEqual(1, len(findings))
        self.assertEqual("Medium", findings[0].severity)
        self.assertEqual("Deployment/sample-ns/sample-api", findings[0].component_name)

    def test_one_result_naming_several_resources_becomes_several_findings(self):
        payload = {
            "apiVersion": "openreports.io/v1alpha1",
            "kind": "ClusterReport",
            "results": [
                {
                    "policy": "require-labels",
                    "rule": "check-team-label",
                    "result": "fail",
                    "severity": "low",
                    "message": "The team label is required.",
                    "resources": [
                        {"kind": "Pod", "namespace": "sample-ns", "name": "first"},
                        {"kind": "Pod", "namespace": "sample-ns", "name": "second"},
                    ],
                },
            ],
        }
        findings = KyvernoParser().get_findings(io.StringIO(json.dumps(payload)), Test())
        self.assertEqual(2, len(findings))
        self.assertEqual(
            {"Pod/sample-ns/first", "Pod/sample-ns/second"},
            {f.component_name for f in findings},
        )
