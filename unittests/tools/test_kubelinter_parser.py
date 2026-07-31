import io
import json

from dojo.models import Finding, Test
from dojo.tools.kubelinter.parser import KubeLinterParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path, skip_unless_v3


class TestKubeLinterParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("kubelinter") / filename).open(encoding="utf-8") as file:
            return list(KubeLinterParser().get_findings(file, Test()))

    def report(self, filename):
        with (get_unit_tests_scans_path("kubelinter") / filename).open(encoding="utf-8") as file:
            return json.load(file)

    def test_scan_type_metadata(self):
        parser = KubeLinterParser()
        self.assertEqual(["KubeLinter Scan"], parser.get_scan_types())
        self.assertEqual("KubeLinter Scan", parser.get_label_for_scan_types("KubeLinter Scan"))
        self.assertIn("kube-linter lint", parser.get_description_for_scan_types("KubeLinter Scan"))

    def test_no_vuln(self):
        """
        A clean scan reports "Reports": null, not an empty list.

        That is worth pinning: a parser that iterated the value directly would fail on a clean
        report, which is the one case a user is most likely to hit first. The document is also far
        from empty - KubeLinter always emits its whole enabled-check registry - so file size says
        nothing about whether anything was found.
        """
        report = self.report("kubelinter_no_vuln.json")
        self.assertIsNone(report["Reports"])
        self.assertGreater(len(report["Checks"]), 0, "the enabled checks are listed regardless")
        self.assertEqual(0, len(self.parse("kubelinter_no_vuln.json")))

    def test_null_reports_is_tolerated(self):
        self.assertEqual(
            [],
            list(KubeLinterParser().get_findings(io.StringIO('{"Reports": null}'), Test())),
        )

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("kubelinter_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `kube-linter lint --format json` run."""
        findings = self.parse("kubelinter_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("no-read-only-root-fs", finding.title)
        self.assertEqual("no-read-only-root-fs", finding.vuln_id_from_tool)
        self.assertEqual("Medium", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("/manifests/single.yaml", finding.file_path)
        self.assertEqual("Deployment/generic-app", finding.component_name)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

        self.assertIn('container "server" does not have a read-only root file system',
                      finding.description)
        self.assertIn("**Object:** Deployment (apps/v1)", finding.description)

    def test_remediation_becomes_the_mitigation(self):
        """
        KubeLinter ships a remediation sentence with every check.

        That is exactly what the mitigation field is for, so it is not buried in the description.
        """
        finding = self.parse("kubelinter_one_vuln.json")[0]
        self.assertEqual(
            "Set readOnlyRootFilesystem to true in the container securityContext.",
            finding.mitigation,
        )

    def test_no_line_number(self):
        """KubeLinter reports the manifest but never a line, so the finding has no line."""
        finding = self.parse("kubelinter_one_vuln.json")[0]
        self.assertIsNone(getattr(finding, "line", None))

    def test_unset_namespace_is_explicit(self):
        """
        An empty namespace means the manifest did not set one.

        Saying so beats printing nothing, and distinguishes it from a namespace called "default".
        """
        finding = self.parse("kubelinter_one_vuln.json")[0]
        self.assertIn("**Namespace:** (not set)", finding.description)

    def test_many_vuln(self):
        findings = self.parse("kubelinter_many_vuln.json")
        self.assertEqual(7, len(findings))
        for finding in findings:
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("/manifests/many.yaml", finding.file_path)
            self.assertEqual("Deployment/generic-app", finding.component_name)
            self.assertTrue(finding.mitigation, "every KubeLinter check carries a remediation")

    def test_many_vuln_checks(self):
        findings = self.parse("kubelinter_many_vuln.json")
        self.assertEqual(
            [
                "latest-tag",
                "no-read-only-root-fs",
                "privilege-escalation-container",
                "privileged-container",
                "run-as-non-root",
                "unset-cpu-requirements",
                "unset-memory-requirements",
            ],
            sorted(finding.title for finding in findings),
        )

    def test_severity_is_a_documented_constant(self):
        """
        KubeLinter grades nothing, so every finding imports at one level.

        Its default set mixes security checks (privileged-container, run-as-non-root) with
        reliability ones (unset-cpu-requirements), and inventing a split would be guesswork.
        """
        findings = self.parse("kubelinter_many_vuln.json")
        self.assertEqual({"Medium"}, {finding.severity for finding in findings})

    def test_namespaced_object_is_named_with_its_namespace(self):
        report = io.StringIO(json.dumps({"Reports": [{
            "Check": "privileged-container",
            "Diagnostic": {"Message": "m"},
            "Object": {"K8sObject": {
                "Namespace": "payments",
                "Name": "api",
                "GroupVersionKind": {"Group": "apps", "Version": "v1", "Kind": "StatefulSet"},
            }},
        }]}))
        finding = list(KubeLinterParser().get_findings(report, Test()))[0]
        self.assertEqual("payments/StatefulSet/api", finding.component_name)
        self.assertIn("**Namespace:** payments", finding.description)

    def test_report_without_a_file_path(self):
        """Linting a live cluster yields no FilePath, and the finding must still import."""
        report = io.StringIO(json.dumps({"Reports": [{
            "Check": "run-as-non-root",
            "Diagnostic": {"Message": "m"},
            "Object": {"K8sObject": {"Name": "api", "GroupVersionKind": {"Kind": "Pod"}}},
        }]}))
        finding = list(KubeLinterParser().get_findings(report, Test()))[0]
        self.assertIsNone(finding.file_path)
        self.assertEqual("Pod/api", finding.component_name)
        self.assertEqual([], finding.unsaved_locations)

    def test_absent_reports_key(self):
        self.assertEqual([], list(KubeLinterParser().get_findings(io.StringIO("{}"), Test())))

    def test_wrong_shape_is_rejected(self):
        with self.assertRaises(TypeError):
            list(KubeLinterParser().get_findings(io.StringIO("[]"), Test()))
        with self.assertRaises(TypeError):
            list(KubeLinterParser().get_findings(io.StringIO('{"Reports": ["x"]}'), Test()))

    @skip_unless_v3
    def test_locations(self):
        findings = self.parse("kubelinter_one_vuln.json")
        locations = findings[0].unsaved_locations
        self.assertEqual(1, len(locations))
        self.assertEqual("code", locations[0].type)
        self.assertEqual("/manifests/single.yaml", locations[0].data["file_path"])
        self.assertIsNone(locations[0].data["line"])
