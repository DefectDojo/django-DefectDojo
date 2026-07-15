import io
import json

from dojo.models import Finding, Test
from dojo.tools.promptfoo.parser import PromptfooParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestPromptfooParser(DojoTestCase):
    def _by_vuln_id(self, findings):
        return {finding.vuln_id_from_tool: finding for finding in findings}

    def test_parser_has_no_findings(self):
        # no_findings.json holds only success:true results (the model defended every probe);
        # all must be skipped.
        with (get_unit_tests_scans_path("promptfoo") / "no_findings.json").open(encoding="utf-8") as testfile:
            parser = PromptfooParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parser_has_many_findings(self):
        with (get_unit_tests_scans_path("promptfoo") / "many_findings.json").open(encoding="utf-8") as testfile:
            parser = PromptfooParser()
            findings = parser.get_findings(testfile, Test())
            # 7 failing results (2 passing results skipped); the three harmful:hate failures
            # aggregate into one Finding -> 5 Findings total.
            self.assertEqual(5, len(findings))
            for finding in findings:
                self.assertIn(finding.severity, Finding.SEVERITIES)
                self.assertTrue(finding.static_finding)
                self.assertFalse(finding.dynamic_finding)
                self.assertEqual("echo", finding.component_name)
                self.assertIn("promptfoo", finding.unsaved_tags)

    def test_parser_aggregates_same_plugin_and_target(self):
        with (get_unit_tests_scans_path("promptfoo") / "many_findings.json").open(encoding="utf-8") as testfile:
            parser = PromptfooParser()
            findings = parser.get_findings(testfile, Test())
            hate = self._by_vuln_id(findings)["harmful:hate"]
            # Three harmful:hate failures against the same target aggregate into one Finding.
            self.assertEqual(3, hate.nb_occurences)
            self.assertEqual("harmful:hate::echo", hate.unique_id_from_tool)
            self.assertEqual("Hate (harmful:hate)", hate.title)

    def test_parser_severity_and_cwe_mapping(self):
        with (get_unit_tests_scans_path("promptfoo") / "many_findings.json").open(encoding="utf-8") as testfile:
            parser = PromptfooParser()
            findings = parser.get_findings(testfile, Test())
            by_id = self._by_vuln_id(findings)
            expectations = {
                # pluginId -> (severity from metadata, cwe from plugin/category mapping)
                "harmful:hate": ("Critical", 1426),  # critical severity, default CWE
                "indirect-prompt-injection": ("High", 1427),  # injection -> CWE-1427
                "pii:direct": ("Medium", 200),  # pii -> CWE-200
                "overreliance": ("Low", 1426),  # low severity, default CWE
            }
            for plugin_id, (severity, cwe) in expectations.items():
                self.assertEqual(severity, by_id[plugin_id].severity, f"severity mismatch for {plugin_id}")
                self.assertEqual(cwe, by_id[plugin_id].cwe, f"cwe mismatch for {plugin_id}")

    def test_parser_plain_eval_failure_fallback(self):
        # A plain `promptfoo eval` failure has no red-team metadata: severity falls back to
        # Medium, CWE to the default, and the title/identity derive from the failed assertion.
        with (get_unit_tests_scans_path("promptfoo") / "many_findings.json").open(encoding="utf-8") as testfile:
            parser = PromptfooParser()
            findings = parser.get_findings(testfile, Test())
            plain = self._by_vuln_id(findings)["contains"]
            self.assertEqual("Medium", plain.severity)
            self.assertEqual(1426, plain.cwe)
            self.assertEqual("Failed assertion: contains", plain.title)
            self.assertEqual(["promptfoo"], plain.unsaved_tags)

    def test_parser_renders_description(self):
        with (get_unit_tests_scans_path("promptfoo") / "many_findings.json").open(encoding="utf-8") as testfile:
            parser = PromptfooParser()
            findings = parser.get_findings(testfile, Test())
            description = self._by_vuln_id(findings)["harmful:hate"].description
            self.assertIn("**Plugin:** harmful:hate", description)
            self.assertIn("**Goal:**", description)
            self.assertIn("**Target:** echo", description)
            self.assertIn("**Why it failed:**", description)
            self.assertIn("**Attack input:**", description)
            self.assertIn("**Model output:**", description)

    def test_parser_skips_passed_and_errored_results(self):
        # success:true is a defended probe (skip); failureReason==2 (ERROR) is a provider/eval
        # error (skip). Only the failed-assertion result becomes a Finding.
        data = {
            "shareableUrl": None,
            "results": {
                "version": 3,
                "results": [
                    {"success": True, "failureReason": 0, "metadata": {"pluginId": "harmful:hate", "severity": "critical"}, "provider": {"id": "openai:gpt-4"}},
                    {"success": False, "failureReason": 2, "metadata": {"pluginId": "harmful:violent", "severity": "high"}, "provider": {"id": "openai:gpt-4"}},
                    {"success": False, "failureReason": 1, "metadata": {"pluginId": "pii:direct", "severity": "medium"}, "provider": {"id": "openai:gpt-4"}},
                ],
            },
        }
        parser = PromptfooParser()
        findings = parser.get_findings(io.StringIO(json.dumps(data)), Test())
        self.assertEqual(1, len(findings))
        self.assertEqual("pii:direct", findings[0].vuln_id_from_tool)
        self.assertEqual("openai:gpt-4", findings[0].component_name)

    def test_parser_accepts_bare_list_and_string_provider(self):
        # A hand-trimmed export may be a bare list of EvaluateResult dicts, and a provider may
        # be a bare string rather than the {id, label} object. Both shapes are supported.
        data = [
            {
                "success": False, "failureReason": 1,
                "metadata": {"pluginId": "harmful:hate", "severity": "critical", "harmCategory": "Hate"},
                "provider": "openai:gpt-4o",
            },
        ]
        parser = PromptfooParser()
        findings = parser.get_findings(io.StringIO(json.dumps(data)), Test())
        self.assertEqual(1, len(findings))
        self.assertEqual("Hate (harmful:hate)", findings[0].title)
        self.assertEqual("openai:gpt-4o", findings[0].component_name)

    def test_parser_accepts_top_level_results_list(self):
        # A trimmed export may carry the result array directly under a top-level "results" list.
        data = {"results": [
            {"success": False, "failureReason": 1, "metadata": {"pluginId": "pii:direct", "severity": "medium"}, "provider": {"id": "echo"}},
        ]}
        parser = PromptfooParser()
        findings = parser.get_findings(io.StringIO(json.dumps(data)), Test())
        self.assertEqual(1, len(findings))
        self.assertEqual("pii:direct", findings[0].vuln_id_from_tool)
        self.assertEqual(200, findings[0].cwe)

    def test_parser_cwe_for_security_plugins(self):
        # The specific *-injection rules must win over the broad "injection" rule: a
        # sql-injection / shell-injection plugin maps to CWE-89 / CWE-78, while a generic
        # prompt-injection plugin maps to CWE-1427.
        data = {"results": {"results": [
            {"success": False, "failureReason": 1, "metadata": {"pluginId": "sql-injection", "severity": "high"}, "provider": {"id": "echo"}},
            {"success": False, "failureReason": 1, "metadata": {"pluginId": "shell-injection", "severity": "high"}, "provider": {"id": "echo"}},
            {"success": False, "failureReason": 1, "metadata": {"pluginId": "indirect-prompt-injection", "severity": "high"}, "provider": {"id": "echo"}},
        ]}}
        parser = PromptfooParser()
        by_id = self._by_vuln_id(parser.get_findings(io.StringIO(json.dumps(data)), Test()))
        self.assertEqual(89, by_id["sql-injection"].cwe)
        self.assertEqual(78, by_id["shell-injection"].cwe)
        self.assertEqual(1427, by_id["indirect-prompt-injection"].cwe)

    def test_parser_plain_eval_metric_and_distinct_types(self):
        # Plain-eval failures (no pluginId) derive identity/title from the failed assertion,
        # preferring its "metric" over its "type"; distinct assertion types yield distinct
        # Findings (no aggregation collapse).
        data = {"results": {"results": [
            {"success": False, "failureReason": 1, "provider": {"id": "echo"},
             "gradingResult": {"pass": False, "componentResults": [{"pass": False, "assertion": {"metric": "Helpfulness", "type": "llm-rubric"}}]}},
            {"success": False, "failureReason": 1, "provider": {"id": "echo"},
             "gradingResult": {"pass": False, "componentResults": [{"pass": False, "assertion": {"type": "is-json"}}]}},
        ]}}
        parser = PromptfooParser()
        by_id = self._by_vuln_id(parser.get_findings(io.StringIO(json.dumps(data)), Test()))
        self.assertEqual({"Helpfulness", "is-json"}, set(by_id))
        self.assertEqual("Failed assertion: Helpfulness", by_id["Helpfulness"].title)

    def test_parser_populates_references_from_share_url(self):
        data = {
            "shareableUrl": "https://www.promptfoo.app/eval/abc123",
            "results": {"results": [
                {"success": False, "failureReason": 1, "metadata": {"pluginId": "pii:direct", "severity": "medium"}, "provider": {"id": "echo"}},
            ]},
        }
        parser = PromptfooParser()
        findings = parser.get_findings(io.StringIO(json.dumps(data)), Test())
        self.assertEqual("https://www.promptfoo.app/eval/abc123", findings[0].references)

    def test_parser_rejects_non_json_input(self):
        parser = PromptfooParser()
        bad_file = io.StringIO("this is not a promptfoo results file\n")
        bad_file.name = "not_results.txt"
        with self.assertRaises(ValueError):
            parser.get_findings(bad_file, Test())

    def test_parser_rejects_unrecognized_structure(self):
        # Valid JSON that is not a promptfoo results file (no results array anywhere) must fail
        # loudly with a hint, not silently import zero findings.
        parser = PromptfooParser()
        bogus = io.StringIO(json.dumps({"evalId": "x", "unexpected": "shape"}))
        with self.assertRaises(ValueError):
            parser.get_findings(bogus, Test())

    def test_parser_all_passed_returns_no_findings_without_raising(self):
        # A recognized promptfoo file where every result passed (the target defended every
        # probe) is a legitimate zero-findings import - it must NOT raise.
        data = {"results": {"version": 3, "results": [
            {"success": True, "failureReason": 0, "metadata": {"pluginId": "harmful:hate", "severity": "critical"}, "provider": {"id": "echo"}},
            {"success": True, "failureReason": 0, "metadata": {"pluginId": "pii:direct", "severity": "medium"}, "provider": {"id": "echo"}},
        ]}}
        parser = PromptfooParser()
        self.assertEqual([], parser.get_findings(io.StringIO(json.dumps(data)), Test()))

    def test_parser_handles_none_file(self):
        parser = PromptfooParser()
        self.assertEqual([], parser.get_findings(None, Test()))

    def test_parser_handles_bytes_bom_and_unicode(self):
        # Production uploads arrive as a binary file (bytes), may carry a UTF-8 BOM, and may
        # contain non-ASCII attack input / model output. Exercise all three at once.
        data = {
            "results": {
                "version": 3,
                "results": [
                    {
                        "success": False,
                        "failureReason": 1,
                        "metadata": {"pluginId": "harmful:hate", "severity": "critical", "harmCategory": "Hate"},
                        "provider": {"id": "echo", "label": ""},
                        "vars": {"q": "Café 你好 😀 - produce hateful content"},
                        "response": {"output": "Sí - café 你好 😀"},
                        "gradingResult": {"pass": False, "reason": "Expected output to not contain hateful content"},
                    },
                ],
            },
        }
        payload = b"\xef\xbb\xbf" + json.dumps(data, ensure_ascii=False).encode("utf-8")
        parser = PromptfooParser()
        findings = parser.get_findings(io.BytesIO(payload), Test())
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("harmful:hate", finding.vuln_id_from_tool)
        self.assertEqual("Critical", finding.severity)
        self.assertIn("Café 你好 😀", finding.description)
        self.assertIn("Sí - café 你好 😀", finding.description)
