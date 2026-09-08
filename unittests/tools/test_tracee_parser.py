import io

from dojo.models import Test
from dojo.tools.tracee.parser import TraceeParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestTraceeParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("tracee") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = TraceeParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("tracee") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = TraceeParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Traced event: setgid", finding.title)
            self.assertEqual("setgid", finding.vuln_id_from_tool)
            self.assertEqual("sample-container", finding.component_name)
            self.assertEqual("alpine:latest", finding.component_version)
            self.assertFalse(finding.static_finding)
            self.assertTrue(finding.dynamic_finding)

            with self.subTest("a traced event carries no verdict from Tracee, so it imports as Info"):
                self.assertEqual("Info", finding.severity)

            with self.subTest("the syscall context is preserved"):
                self.assertIn("**Event:** setgid", finding.description)
                self.assertIn("**Syscall:** setgid", finding.description)
                self.assertIn("**Return value:** 0", finding.description)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("tracee") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = TraceeParser().get_findings(testfile, Test())
            self.assertEqual(20, len(findings))

            with self.subTest("all four traced event types are imported"):
                self.assertEqual(
                    {"setgid": 6, "setuid": 6, "sched_process_exec": 6, "security_inode_unlink": 2},
                    {
                        name: len([f for f in findings if f.vuln_id_from_tool == name])
                        for name in {f.vuln_id_from_tool for f in findings}
                    },
                )

            with self.subTest("traced events do not invent a severity"):
                self.assertEqual({"Info"}, {f.severity for f in findings})

            with self.subTest("event arguments are recorded"):
                unlink = [f for f in findings if f.vuln_id_from_tool == "security_inode_unlink"]
                self.assertIn("**Arguments:**", unlink[0].description)
                self.assertIn("pathname", unlink[0].description)

    def test_signature_detection_uses_tracees_own_severity(self):
        """
        A signature detection is a verdict and carries a severity; a traced event does not.

        The severity scale is the Severity enum in tracee's api/v1beta1/threat.proto:
        INFO=0 LOW=1 MEDIUM=2 HIGH=3 CRITICAL=4.
        """
        parser = TraceeParser()
        expected = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
        for value, severity in expected.items():
            with self.subTest(severity=value):
                finding = parser._to_finding(
                    {
                        "eventName": "anti_debugging",
                        "container": {"name": "sample-container", "image": "alpine:latest"},
                        "metadata": {
                            "Description": "Process uses anti-debugging technique to block debugger.",
                            "Tags": ["container"],
                            "Properties": {
                                "Category": "defense-evasion",
                                "Technique": "Debugger Evasion",
                                "Severity": value,
                                "signatureID": "TRC-102",
                                "signatureName": "Anti-Debugging detected",
                                "external_id": "T1622",
                            },
                        },
                    },
                    Test(),
                )
                self.assertEqual(severity, finding.severity)

        with self.subTest("a detection is titled and tracked by its signature id"):
            self.assertEqual("TRC-102: Anti-Debugging detected", finding.title)
            self.assertEqual("TRC-102", finding.vuln_id_from_tool)
            self.assertIn("**Category:** defense-evasion", finding.description)
            self.assertIn("**MITRE id:** T1622", finding.description)
            self.assertIn("T1622", finding.unsaved_tags)

        with self.subTest("an unrecognised severity value does not crash the import"):
            finding = parser._to_finding(
                {"eventName": "x", "metadata": {"Properties": {"Severity": 99, "signatureID": "TRC-1"}}},
                Test(),
            )
            self.assertEqual("Medium", finding.severity)

    def test_tracee_log_lines_are_not_findings(self):
        """Tracee writes its own structured log lines onto the same stream."""
        payload = (
            '{"level":"warn","ts":1786376859.02,"msg":"KConfig: assuming kconfig values"}\n'
            '{"timestamp":1786376861034623572,"eventName":"setuid","syscall":"setuid",'
            '"container":{"name":"sample-container"},"args":[]}\n'
        )
        findings = TraceeParser().get_findings(io.StringIO(payload), Test())
        self.assertEqual(1, len(findings))
        self.assertEqual("setuid", findings[0].vuln_id_from_tool)
