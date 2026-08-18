import io
import json

from dojo.models import Test
from dojo.tools.capa.parser import CapaParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestCapaParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("capa") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = CapaParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("capa") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = CapaParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("accept command line arguments (host-interaction/cli)", finding.title)
            self.assertEqual("accept command line arguments", finding.vuln_id_from_tool)
            self.assertEqual("Info", finding.severity)
            self.assertIn("**Namespace:** host-interaction/cli", finding.description)
            self.assertIn("Command and Scripting Interpreter", finding.description)
            self.assertIn("**Sample SHA256:**", finding.description)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_capabilities_are_intelligence_not_defects(self):
        with (get_unit_tests_scans_path("capa") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = CapaParser().get_findings(testfile, Test())
            self.assertEqual(9, len(findings))
            self.assertEqual({"Info"}, {f.severity for f in findings})

            with self.subTest("every capability is attributed to the same sample"):
                self.assertEqual(1, len({f.component_name for f in findings}))

            with self.subTest("capability names are unique"):
                self.assertEqual(9, len({f.vuln_id_from_tool for f in findings}))

    def test_library_and_subscope_rules_are_not_capabilities(self):
        """Capa emits helper rules used to build other matches; they are not results."""
        parser = CapaParser()
        report = {
            "meta": {"sample": {"sha256": "abc"}},
            "rules": {
                "real": {"meta": {"name": "real capability"}, "matches": []},
                "helper": {"meta": {"name": "helper", "lib": True}, "matches": []},
                "sub": {"meta": {"name": "sub", "is_subscope_rule": True}, "matches": []},
            },
        }
        findings = parser.get_findings(io.StringIO(json.dumps(report)), Test())
        self.assertEqual(1, len(findings))
        self.assertEqual("real capability", findings[0].vuln_id_from_tool)

    def test_attack_and_mbc_entries_are_rendered_with_ids(self):
        parser = CapaParser()
        self.assertEqual(
            ["Command and Scripting Interpreter (T1059)"],
            parser._techniques([{"technique": "Command and Scripting Interpreter", "id": "T1059"}]),
        )
        self.assertEqual(["Subtech (T1059.001)"], parser._techniques([{"subtechnique": "Subtech", "id": "T1059.001"}]))
        self.assertEqual(["Bare"], parser._techniques([{"technique": "Bare"}]))
        self.assertEqual([], parser._techniques(None))
