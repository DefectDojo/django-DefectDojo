import io

from dojo.models import Test
from dojo.tools.falco.parser import FalcoParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestFalcoParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("falco") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = FalcoParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("falco") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = FalcoParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Read sensitive file untrusted", finding.title)
            self.assertEqual("Read sensitive file untrusted", finding.vuln_id_from_tool)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("sample-container", finding.component_name)
            self.assertEqual("/etc/shadow", finding.file_path)

            with self.subTest("an alert is runtime evidence, not a static defect"):
                self.assertFalse(finding.static_finding)
                self.assertTrue(finding.dynamic_finding)

            with self.subTest("the process context that triggered the rule is preserved"):
                self.assertIn("**Process:** cat", finding.description)
                self.assertIn("**Command line:** cat /etc/shadow", finding.description)
                self.assertIn("**User:** root", finding.description)
                self.assertIn("**Event type:** openat", finding.description)

            with self.subTest("MITRE technique ids arrive as tags"):
                self.assertIn("T1555", finding.unsaved_tags)
                self.assertIn("mitre_credential_access", finding.unsaved_tags)

    def test_parse_many_findings(self):
        """Falco priorities are the syslog levels, so different rules land on different severities."""
        with (get_unit_tests_scans_path("falco") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = FalcoParser().get_findings(testfile, Test())
            self.assertEqual(5, len(findings))

            with self.subTest("Warning becomes Medium and Notice becomes Low"):
                self.assertEqual(4, len([f for f in findings if f.severity == "Medium"]))
                self.assertEqual(1, len([f for f in findings if f.severity == "Low"]))
                self.assertEqual(
                    "Terminal shell in container",
                    next(f.title for f in findings if f.severity == "Low"),
                )

            with self.subTest("each alert is kept, so repeats of a rule are not collapsed on import"):
                repeated = [f for f in findings if f.title == "Read sensitive file untrusted"]
                self.assertEqual(3, len(repeated))
                self.assertEqual(3, len({f.description for f in repeated}))

            with self.subTest("every alert names its rule and its workload"):
                for finding in findings:
                    self.assertTrue(finding.vuln_id_from_tool)
                    self.assertIsNotNone(finding.component_name)

    def test_priority_mapping_covers_the_whole_syslog_scale(self):
        """Falco can emit any syslog priority, so all eight must map to a real severity."""
        parser = FalcoParser()
        expected = {
            "Emergency": "Critical",
            "Alert": "Critical",
            "Critical": "Critical",
            "Error": "High",
            "Warning": "Medium",
            "Notice": "Low",
            "Informational": "Info",
            "Debug": "Info",
        }
        for priority, severity in expected.items():
            with self.subTest(priority=priority):
                finding = parser._to_finding({"rule": "Some rule", "priority": priority}, Test())
                self.assertEqual(severity, finding.severity)

        with self.subTest("an unknown priority still yields a severity"):
            finding = parser._to_finding({"rule": "Some rule", "priority": "Nonsense"}, Test())
            self.assertEqual("Medium", finding.severity)

    def test_parse_json_array_output(self):
        """Some Falco outputs batch alerts into a JSON array rather than one object per line."""
        payload = (
            '[{"rule": "Terminal shell in container", "priority": "Notice", '
            '"output": "A shell was spawned", "output_fields": {"container.name": "sample-container"}, '
            '"tags": ["container"]}]'
        )
        findings = FalcoParser().get_findings(io.StringIO(payload), Test())
        self.assertEqual(1, len(findings))
        self.assertEqual("Low", findings[0].severity)
        self.assertEqual("sample-container", findings[0].component_name)
