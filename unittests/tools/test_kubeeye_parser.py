import io
import json

from dojo.models import Test
from dojo.tools.kubeeye.parser import KubeEyeParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestKubeEyeParser(DojoTestCase):

    def test_parse_no_findings(self):
        """Every inspection ran and asserted false, meaning nothing was found."""
        with (get_unit_tests_scans_path("kubeeye") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = KubeEyeParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("kubeeye") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = KubeEyeParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Sysctl setting: net.ipv4.conf.all.rp_filter", finding.title)
            self.assertEqual("net.ipv4.conf.all.rp_filter", finding.vuln_id_from_tool)
            self.assertEqual("High", finding.severity)
            self.assertEqual("worker-1", finding.component_name)
            self.assertIn("**Level:** danger", finding.description)
            self.assertIn("**Cluster:** default", finding.description)
            self.assertIn("**value:** 0", finding.description)

    def test_parse_many_findings(self):
        """Results are spread across one list per inspection kind, and all must be walked."""
        with (get_unit_tests_scans_path("kubeeye") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = KubeEyeParser().get_findings(testfile, Test())
            self.assertEqual(9, len(findings))

            with self.subTest("checks that asserted false are skipped"):
                # nodeInfo and sysctlResult each hold one passing entry in the fixture.
                self.assertNotIn("check inode usage", {f.vuln_id_from_tool for f in findings})
                self.assertNotIn("net.ipv4.ip_forward", {f.vuln_id_from_tool for f in findings})

            with self.subTest("the three KubeEye levels map to three severities"):
                self.assertEqual(4, len([f for f in findings if f.severity == "High"]))
                self.assertEqual(4, len([f for f in findings if f.severity == "Medium"]))
                self.assertEqual(1, len([f for f in findings if f.severity == "Info"]))

            with self.subTest("every inspection kind is represented and labelled"):
                self.assertEqual(
                    {
                        "Node information", "File change", "Sysctl setting", "Systemd unit",
                        "Command", "Component", "Service connectivity", "Prometheus rule",
                    },
                    {f.title.split(":", 1)[0] for f in findings},
                )

            with self.subTest("a file change records its path and diff"):
                file_change = next(f for f in findings if f.title.startswith("File change"))
                self.assertEqual("/etc/kubernetes/kubelet.conf", file_change.file_path)
                self.assertIn("readOnlyPort", file_change.description)

            with self.subTest("a service check is attributed to its namespace"):
                service = next(f for f in findings if f.title.startswith("Service connectivity"))
                self.assertEqual("kube-system", service.component_name)
                self.assertIn("**endpoint:** 10.96.0.10:53", service.description)

    def test_a_list_of_inspect_results_is_accepted(self):
        payload = {
            "apiVersion": "v1",
            "kind": "List",
            "items": [
                {
                    "kind": "InspectResult",
                    "spec": {
                        "inspectCluster": {"name": "default"},
                        "componentResult": [{"name": "kube-scheduler", "assert": True, "level": "danger"}],
                    },
                },
            ],
        }
        findings = KubeEyeParser().get_findings(io.StringIO(json.dumps(payload)), Test())
        self.assertEqual(1, len(findings))
        self.assertEqual("High", findings[0].severity)

    def test_an_unknown_level_still_gets_a_severity(self):
        parser = KubeEyeParser()
        finding = parser._to_finding({"name": "x", "assert": True, "level": "unheard-of"}, "Command", (), None, Test())
        self.assertEqual("Medium", finding.severity)
