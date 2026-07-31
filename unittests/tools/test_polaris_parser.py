import io
import json

from dojo.models import Finding, Test
from dojo.tools.polaris.parser import PolarisParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path, skip_unless_v3


class TestPolarisParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("polaris") / filename).open(encoding="utf-8") as file:
            return list(PolarisParser().get_findings(file, Test()))

    def report(self, filename):
        with (get_unit_tests_scans_path("polaris") / filename).open(encoding="utf-8") as file:
            return json.load(file)

    def test_scan_type_metadata(self):
        parser = PolarisParser()
        self.assertEqual(["Polaris Scan"], parser.get_scan_types())
        self.assertEqual("Polaris Scan", parser.get_label_for_scan_types("Polaris Scan"))
        self.assertIn("polaris audit", parser.get_description_for_scan_types("Polaris Scan"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("polaris_no_vuln.json")))

    def test_passing_checks_are_not_findings(self):
        """
        Polaris reports every check it ran, passing and failing alike.

        The clean report contains dozens of results with Success true and scores 100; importing
        anything but the failures would turn a compliant manifest into dozens of findings.
        """
        report = self.report("polaris_no_vuln.json")
        self.assertEqual(100, report["Score"])

        successes = 0
        for result in report["Results"]:
            successes += sum(1 for c in (result.get("Results") or {}).values() if c["Success"])
            pod = result.get("PodResult") or {}
            successes += sum(1 for c in (pod.get("Results") or {}).values() if c["Success"])
            for container in pod.get("ContainerResults") or []:
                successes += sum(1 for c in (container.get("Results") or {}).values() if c["Success"])
        self.assertGreater(successes, 0, "the fixture is meant to contain passing checks")
        self.assertEqual(0, len(self.parse("polaris_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("polaris_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `polaris audit --format json` run."""
        findings = self.parse("polaris_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Filesystem should be read only", finding.title)
        self.assertEqual("notReadOnlyRootFilesystem", finding.vuln_id_from_tool)
        self.assertEqual("Medium", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("/manifests/single.yaml", finding.file_path)
        self.assertEqual("Deployment/generic-app/server", finding.component_name)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

        self.assertIn("**Check:** notReadOnlyRootFilesystem", finding.description)
        self.assertIn("**Category:** Security", finding.description)
        self.assertIn("**Applies to:** container", finding.description)
        self.assertIn("**Container:** server", finding.description)

    def test_many_vuln(self):
        findings = self.parse("polaris_many_vuln.json")
        self.assertEqual(21, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertEqual("/manifests/many.yaml", finding.file_path)

    def test_the_three_nesting_levels_are_all_walked(self):
        """
        A Polaris check applies to the workload, its pod template, or one container.

        Each level keeps results in its own map, so all three have to be walked - the many_vuln
        report has findings from every level, and missing one would silently drop findings.
        """
        findings = self.parse("polaris_many_vuln.json")
        scopes = {}
        for finding in findings:
            for line in finding.description.split("\n"):
                if line.startswith("**Applies to:** "):
                    scopes.setdefault(line.removeprefix("**Applies to:** "), 0)
                    scopes[line.removeprefix("**Applies to:** ")] += 1
        self.assertEqual({"object", "pod", "container"}, set(scopes))
        self.assertEqual(3, scopes["object"])
        self.assertEqual(4, scopes["pod"])
        self.assertEqual(14, scopes["container"])

    def test_danger_and_warning_map_to_different_severities(self):
        findings = self.parse("polaris_many_vuln.json")
        by_check = {f.vuln_id_from_tool: f.severity for f in findings}
        self.assertEqual("High", by_check["runAsPrivileged"])
        self.assertEqual("High", by_check["runAsRootAllowed"])
        self.assertEqual("High", by_check["privilegeEscalationAllowed"])
        self.assertEqual("High", by_check["tagNotSpecified"])
        self.assertEqual("Medium", by_check["cpuLimitsMissing"])
        self.assertEqual({"High", "Medium"}, set(by_check.values()))

    def test_container_findings_name_the_container(self):
        findings = self.parse("polaris_many_vuln.json")
        container_findings = [f for f in findings if f.component_name.endswith("/server")]
        self.assertEqual(14, len(container_findings))
        for finding in container_findings:
            self.assertEqual("Deployment/generic-app/server", finding.component_name)

    def test_severity_map(self):
        parser = PolarisParser()
        for level, expected in [("danger", "High"), ("warning", "Medium"), ("ignore", "Info")]:
            report = io.StringIO(json.dumps({"Results": [{
                "Kind": "Pod", "Name": "p",
                "Results": {"someCheck": {"Success": False, "Severity": level, "Message": "m"}},
            }]}))
            self.assertEqual(expected, list(parser.get_findings(report, Test()))[0].severity)

        report = io.StringIO(json.dumps({"Results": [{
            "Kind": "Pod", "Name": "p",
            "Results": {"someCheck": {"Success": False, "Severity": "novel", "Message": "m"}},
        }]}))
        self.assertEqual("Medium", list(parser.get_findings(report, Test()))[0].severity)

    def test_cluster_audit_has_no_file_path(self):
        """
        Polaris can audit a live cluster, and then SourceName is a cluster name.

        Reporting it as file_path would be wrong, so the path is only used when SourceType says the
        source was a path.
        """
        report = io.StringIO(json.dumps({
            "SourceType": "Cluster",
            "SourceName": "production-cluster",
            "Results": [{
                "Kind": "Deployment", "Name": "api", "Namespace": "payments",
                "Results": {"someCheck": {"Success": False, "Severity": "danger", "Message": "m"}},
            }],
        }))
        finding = list(PolarisParser().get_findings(report, Test()))[0]
        self.assertIsNone(finding.file_path)
        self.assertEqual("payments/Deployment/api", finding.component_name)
        self.assertEqual([], finding.unsaved_locations)

    def test_absent_results_key(self):
        self.assertEqual([], list(PolarisParser().get_findings(io.StringIO("{}"), Test())))

    def test_wrong_shape_is_rejected(self):
        with self.assertRaises(TypeError):
            list(PolarisParser().get_findings(io.StringIO("[]"), Test()))
        with self.assertRaises(TypeError):
            list(PolarisParser().get_findings(io.StringIO('{"Results": ["x"]}'), Test()))

    @skip_unless_v3
    def test_locations(self):
        findings = self.parse("polaris_one_vuln.json")
        locations = findings[0].unsaved_locations
        self.assertEqual(1, len(locations))
        self.assertEqual("code", locations[0].type)
        self.assertEqual("/manifests/single.yaml", locations[0].data["file_path"])
