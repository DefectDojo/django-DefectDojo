import io
import json

from dojo.models import Test
from dojo.tools.pyrit.parser import PyRITParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestPyRITParser(DojoTestCase):

    def test_parse_no_findings(self):
        """The only attack in the file failed, which means the target's guardrails held."""
        with (get_unit_tests_scans_path("pyrit") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = PyRITParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("pyrit") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = PyRITParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("High", finding.severity)
            self.assertEqual("RedTeamingAttack", finding.vuln_id_from_tool)
            self.assertIn("Persuade the model", finding.title)
            self.assertFalse(finding.static_finding)
            self.assertTrue(finding.dynamic_finding)

            with self.subTest("the objective and the outcome are both recorded"):
                self.assertIn("**Outcome:** success", finding.description)
                self.assertIn("**Objective:** Persuade the model", finding.description)
                self.assertIn("**Turns executed:** 4", finding.description)

            with self.subTest("the scorer's verdict is carried through"):
                self.assertIn("**Score type:** true_false", finding.description)
                self.assertIn("**Score rationale:**", finding.description)

            with self.subTest("the harm category is tagged"):
                self.assertIn("illegal", finding.unsaved_tags)
                self.assertIn("pyrit-outcome-success", finding.unsaved_tags)

    def test_parse_many_findings(self):
        """The outcome decides severity, and a failed attack is not imported at all."""
        with (get_unit_tests_scans_path("pyrit") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = PyRITParser().get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

            by_strategy = {f.vuln_id_from_tool: f for f in findings}
            with self.subTest("success is High, undetermined is Low, error is Info"):
                self.assertEqual("High", by_strategy["RedTeamingAttack"].severity)
                self.assertEqual("Low", by_strategy["CrescendoAttack"].severity)
                self.assertEqual("Info", by_strategy["PromptSendingAttack"].severity)

            with self.subTest("the failed attack against the same strategy is excluded"):
                # PromptSendingAttack appears twice in the fixture: once failure, once error.
                self.assertEqual(1, len([f for f in findings if f.vuln_id_from_tool == "PromptSendingAttack"]))

            with self.subTest("an infrastructure error says the test did not establish anything"):
                errored = by_strategy["PromptSendingAttack"]
                self.assertIn("did not complete", errored.description)
                self.assertIn("**Error type:** RateLimitError", errored.description)

    def test_a_results_wrapper_object_is_accepted(self):
        payload = {
            "results": [
                {
                    "attack_result_id": "abc",
                    "objective": "Extract the system prompt",
                    "outcome": "success",
                    "atomic_attack_identifier": {"name": "PromptSendingAttack"},
                    "executed_turns": 2,
                    "targeted_harm_categories": [],
                },
            ],
        }
        findings = PyRITParser().get_findings(io.StringIO(json.dumps(payload)), Test())
        self.assertEqual(1, len(findings))
        self.assertEqual("High", findings[0].severity)

    def test_a_missing_outcome_is_treated_as_undetermined(self):
        payload = [{"objective": "Something", "atomic_attack_identifier": {"name": "X"}}]
        findings = PyRITParser().get_findings(io.StringIO(json.dumps(payload)), Test())
        self.assertEqual(1, len(findings))
        self.assertEqual("Low", findings[0].severity)
        self.assertIn("**Outcome:** undetermined", findings[0].description)
