import io
import json

from dojo.models import Finding, Test
from dojo.tools.hiddenlayer.parser import HiddenlayerParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestHiddenlayerParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("hiddenlayer") / filename
        with path.open(encoding="utf-8") as file:
            return list(HiddenlayerParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(HiddenlayerParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def log(self, result=None, rule=None, scan_id="scan-1"):
        rules = [rule] if rule else []
        results = [result or {"ruleId": "RULE_1", "level": "error",
                              "message": {"text": "A finding"}}]
        return {"scan_id": scan_id, "sarif": {"runs": [
            {"tool": {"driver": {"rules": rules}}, "results": results}]}}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the HiddenLayer connector's ScanTypeName verbatim.

        Note it does NOT follow the "<Vendor> - Connectors Import" pattern the other connector scan
        types use, so it cannot be derived - it has to be copied.
        """
        parser = HiddenlayerParser()
        self.assertEqual(["HiddenLayer Model Scan"], parser.get_scan_types())
        self.assertEqual("HiddenLayer Model Scan",
                         parser.get_label_for_scan_types("HiddenLayer Model Scan"))
        self.assertNotIn("HiddenLayer - Connectors Import", parser.get_scan_types())

    def test_this_is_not_the_generic_sarif_scan_type(self):
        """
        DefectDojo already parses SARIF, but under the "SARIF" scan type.

        Findings imported there would not deduplicate against the HiddenLayer connector's, which is
        the whole reason this parser exists.
        """
        self.assertNotIn("SARIF", HiddenlayerParser().get_scan_types())

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("hiddenlayer_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("hiddenlayer_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring convertResult in the connector's finding_converter."""
        findings = self.parse("hiddenlayer_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Unsafe pickle opcode found in the model archive", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("hiddenlayer-scan-0001-PICKLE_DESERIALIZATION-"
                         "generic-model/pytorch_model.bin:42", finding.unique_id_from_tool)
        self.assertEqual("PICKLE_DESERIALIZATION", finding.vuln_id_from_tool)
        self.assertEqual(9.3, finding.cvssv3_score)
        self.assertEqual(502, finding.cwe)
        self.assertEqual("generic-model/pytorch_model.bin", finding.file_path)
        self.assertEqual(42, finding.line)
        self.assertEqual("https://example.com/rules/pickle-deserialization", finding.references)
        self.assertEqual("Re-export the model in the safetensors format.", finding.mitigation)
        self.assertTrue(finding.active)
        self.assertFalse(finding.false_p)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(["cwe-502", "model-integrity", "supply-chain"], finding.unsaved_tags)
        self.assertEqual(
            "**Result message:** Unsafe pickle opcode found in the model archive\n"
            "**Rule name:** UnsafePickleDeserialization\n"
            "**Rule short description:** The model file deserialises untrusted pickle data\n"
            "**Rule full description:** Loading this model executes arbitrary code from the "
            "pickle stream.",
            finding.description,
        )

    def test_many_vuln(self):
        """Six results, but the "pass" result is never imported."""
        self.assertEqual(5, len(self.parse("hiddenlayer_many_vuln.json")))

    def test_a_result_that_is_not_a_failure_is_skipped(self):
        """
        SARIF uses kind for results that are not failures - "pass", "open", "informational".

        Importing those would fill the product with non-findings.
        """
        for kind in ("pass", "open", "informational", "notApplicable", "review"):
            with self.subTest(kind=kind):
                self.assertEqual(0, len(self.parse_string(self.log(
                    result={"ruleId": "RULE_1", "kind": kind, "message": {"text": "A finding"}}))))

    def test_an_absent_kind_means_a_failure(self):
        """SARIF makes kind optional and defaults it to "fail", so an absent kind is imported."""
        findings = self.parse_string(self.log(
            result={"ruleId": "RULE_1", "level": "error", "message": {"text": "A finding"}}))
        self.assertEqual(1, len(findings))

    def test_a_suppressed_result_is_inactive_and_a_false_positive(self):
        """
        SARIF suppression is a reviewer saying this one does not count.

        Recording it as inactive alone would leave it in the open-findings count; recording it as a
        false positive is what its metrics should say.
        """
        finding = self.by_uid("hiddenlayer_many_vuln.json")[
            "hiddenlayer-scan-0001-SUSPICIOUS_IMPORT-generic-model/loader.py:17"]
        self.assertFalse(finding.active)
        self.assertTrue(finding.false_p)

    def test_the_security_severity_property_beats_the_result_level(self):
        """The fixture's first result is level "error" (High) but scores 9.3, which is Critical."""
        finding = self.by_uid("hiddenlayer_many_vuln.json")[
            "hiddenlayer-scan-0001-PICKLE_DESERIALIZATION-generic-model/pytorch_model.bin:42"]
        self.assertEqual("Critical", finding.severity)
        self.assertEqual(9.3, finding.cvssv3_score)

    def test_a_security_severity_word_is_accepted_but_scores_nothing(self):
        """
        The property is documented as a CVSS number, and some tools put a word there instead.

        The word still grades the finding, but there is no score to record - so cvssv3_score stays 0.
        """
        finding = self.by_uid("hiddenlayer_many_vuln.json")[
            "hiddenlayer-scan-0001-SUSPICIOUS_IMPORT-generic-model/loader.py:17"]
        self.assertEqual("High", finding.severity)
        self.assertEqual(0.0, finding.cvssv3_score)

    def test_an_unparseable_security_severity_falls_through_to_the_level(self):
        finding = self.by_uid("hiddenlayer_many_vuln.json")[
            "hiddenlayer-scan-0001-CVE-2000-0001-generic-model/requirements.txt:0"]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual(0.0, finding.cvssv3_score)

    def test_result_levels(self):
        for level, expected in (("note", "Info"), ("warning", "Medium"), ("error", "High")):
            with self.subTest(level=level):
                findings = self.parse_string(self.log(
                    result={"ruleId": "RULE_1", "level": level, "message": {"text": "A finding"}}))
                self.assertEqual(expected, findings[0].severity)

    def test_a_result_with_no_level_is_medium_not_info(self):
        """
        SARIF makes level optional, and a tool that omits it is not saying the result is harmless.

        Defaulting to Info would silently bury it.
        """
        findings = self.parse_string(self.log(
            result={"ruleId": "RULE_1", "message": {"text": "A finding"}}))
        self.assertEqual("Medium", findings[0].severity)

    def test_cvss_score_bands(self):
        for score, expected in (("9", "Critical"), ("9.9", "Critical"), ("7", "High"),
                                ("4", "Medium"), ("0.1", "Low"), ("0", "Info")):
            with self.subTest(score=score):
                findings = self.parse_string(self.log(
                    rule={"id": "RULE_1", "properties": {"security-severity": score}}))
                self.assertEqual(expected, findings[0].severity)

    def test_the_cwe_comes_from_the_rule_relationship_first(self):
        """SARIF has no CWE field; a tool states the taxonomy as a relationship or as a tag."""
        finding = self.by_uid("hiddenlayer_many_vuln.json")[
            "hiddenlayer-scan-0001-PICKLE_DESERIALIZATION-generic-model/pytorch_model.bin:42"]
        self.assertEqual(502, finding.cwe)

    def test_the_cwe_falls_back_to_the_rule_tags_then_the_result_tags(self):
        findings = self.by_uid("hiddenlayer_many_vuln.json")
        from_rule_tag = findings[
            "hiddenlayer-scan-0001-SUSPICIOUS_IMPORT-generic-model/loader.py:17"]
        self.assertEqual(94, from_rule_tag.cwe)
        # This result's rule is not defined in the run at all, so only its own tags are available.
        from_result_tag = findings["hiddenlayer-scan-0001-UNKNOWN_RULE-:0"]
        self.assertEqual(77, from_result_tag.cwe)

    def test_cwe_forms(self):
        for value, expected in (("CWE-502", 502), ("cwe-502", 502), ("external/cwe/cwe-502", 502),
                                ("not a cwe", 0)):
            with self.subTest(value=value):
                findings = self.parse_string(self.log(
                    rule={"id": "RULE_1", "properties": {"tags": [value]}}))
                self.assertEqual(expected, findings[0].cwe)

    def test_a_rule_id_that_is_a_cve_becomes_a_vulnerability_id(self):
        finding = self.by_uid("hiddenlayer_many_vuln.json")[
            "hiddenlayer-scan-0001-CVE-2000-0001-generic-model/requirements.txt:0"]
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)

    def test_a_rule_id_that_is_not_a_cve_has_no_vulnerability_id(self):
        finding = self.by_uid("hiddenlayer_many_vuln.json")[
            "hiddenlayer-scan-0001-PICKLE_DESERIALIZATION-generic-model/pytorch_model.bin:42"]
        self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_a_lowercase_cve_rule_id_is_uppercased(self):
        findings = self.parse_string(self.log(
            result={"ruleId": "cve-2000-0002", "level": "error", "message": {"text": "A finding"}}))
        self.assertEqual(["CVE-2000-0002"], findings[0].unsaved_vulnerability_ids)

    def test_the_title_falls_back_through_the_rule_then_the_rule_id(self):
        cases = (
            ({"id": "RULE_1", "shortDescription": {"text": "Short"},
              "fullDescription": {"text": "Full"}}, "Short"),
            ({"id": "RULE_1", "fullDescription": {"text": "Full"}}, "Full"),
            ({"id": "RULE_1", "name": "TheName"}, "TheName"),
            ({"id": "RULE_1"}, "RULE_1"),
        )
        for rule, expected in cases:
            with self.subTest(expected=expected):
                findings = self.parse_string(self.log(
                    result={"ruleId": "RULE_1", "level": "error", "message": {"text": ""}},
                    rule=rule))
                self.assertEqual(expected, findings[0].title)

    def test_the_title_falls_back_to_the_result_rule_id_when_the_rule_is_missing(self):
        finding = self.by_uid("hiddenlayer_many_vuln.json")["hiddenlayer-scan-0001-UNKNOWN_RULE-:0"]
        self.assertEqual("A result whose rule is not defined in the run", finding.title)

    def test_a_long_title_is_shortened_with_an_ellipsis(self):
        long_message = "x" * 200
        findings = self.parse_string(self.log(
            result={"ruleId": "RULE_1", "level": "error", "message": {"text": long_message}}))
        self.assertEqual(150, len(findings[0].title))
        self.assertTrue(findings[0].title.endswith("..."))
        # The full text is still in the body.
        self.assertIn(long_message, findings[0].description)

    def test_a_description_does_not_repeat_itself(self):
        """
        A rule whose short description merely repeats the result message is not printed twice.

        Nor is a full description that repeats the short one.
        """
        findings = self.parse_string(self.log(
            result={"ruleId": "RULE_1", "level": "error", "message": {"text": "The same text"}},
            rule={"id": "RULE_1", "shortDescription": {"text": "The same text"},
                  "fullDescription": {"text": "The same text"}}))
        self.assertEqual("**Result message:** The same text", findings[0].description)

    def test_the_references_fall_back_to_a_help_text_that_is_a_link(self):
        findings = self.by_uid("hiddenlayer_many_vuln.json")
        self.assertEqual("https://example.com/rules/pickle-deserialization",
                         findings["hiddenlayer-scan-0001-PICKLE_DESERIALIZATION-"
                                 "generic-model/pytorch_model.bin:42"].references)
        self.assertEqual("https://example.com/rules/suspicious-import",
                         findings["hiddenlayer-scan-0001-SUSPICIOUS_IMPORT-"
                                 "generic-model/loader.py:17"].references)

    def test_help_text_that_is_not_a_link_is_not_a_reference(self):
        finding = self.by_uid("hiddenlayer_many_vuln.json")["hiddenlayer-scan-0001-ARCHITECTURE_NOTE-:0"]
        self.assertIsNone(finding.references)

    def test_every_fix_description_becomes_the_mitigation_one_per_line(self):
        finding = self.by_uid("hiddenlayer_many_vuln.json")[
            "hiddenlayer-scan-0001-PICKLE_DESERIALIZATION-generic-model/pytorch_model.bin:42"]
        self.assertEqual("Re-export the model in the safetensors format.\n"
                         "Load the model with weights_only=True.", finding.mitigation)

    def test_no_fixes_leaves_the_mitigation_unset(self):
        finding = self.by_uid("hiddenlayer_many_vuln.json")["hiddenlayer-scan-0001-ARCHITECTURE_NOTE-:0"]
        self.assertIsNone(finding.mitigation)

    def test_a_quoted_start_line_is_accepted(self):
        finding = self.by_uid("hiddenlayer_many_vuln.json")[
            "hiddenlayer-scan-0001-SUSPICIOUS_IMPORT-generic-model/loader.py:17"]
        self.assertEqual(17, finding.line)

    def test_a_location_with_no_region_has_no_line(self):
        finding = self.by_uid("hiddenlayer_many_vuln.json")[
            "hiddenlayer-scan-0001-CVE-2000-0001-generic-model/requirements.txt:0"]
        self.assertEqual("generic-model/requirements.txt", finding.file_path)
        self.assertIsNone(finding.line)

    def test_a_result_with_no_location_has_no_file_path(self):
        finding = self.by_uid("hiddenlayer_many_vuln.json")["hiddenlayer-scan-0001-ARCHITECTURE_NOTE-:0"]
        self.assertIsNone(finding.file_path)
        self.assertIsNone(finding.line)

    def test_the_cwe_taxonomy_prefix_is_stripped_from_tags(self):
        """"external/cwe/cwe-502" reads as "cwe-502", matching DefectDojo's own SARIF parser."""
        finding = self.by_uid("hiddenlayer_many_vuln.json")[
            "hiddenlayer-scan-0001-PICKLE_DESERIALIZATION-generic-model/pytorch_model.bin:42"]
        self.assertIn("cwe-502", finding.unsaved_tags)
        self.assertNotIn("external/cwe/cwe-502", finding.unsaved_tags)

    def test_tags_are_deduplicated_across_the_rule_and_the_result(self):
        findings = self.parse_string(self.log(
            result={"ruleId": "RULE_1", "level": "error", "message": {"text": "A finding"},
                    "properties": {"tags": ["shared", "result-only"]}},
            rule={"id": "RULE_1", "properties": {"tags": ["shared", "rule-only"]}}))
        self.assertEqual(["shared", "rule-only", "result-only"], findings[0].unsaved_tags)

    def test_the_scan_id_may_be_spelled_three_ways(self):
        """
        The scan id is part of every identity the connector builds, and a SARIF log lacks it.

        Without it a file import will not deduplicate against synced findings.
        """
        for key in ("scan_id", "scanId", "scanID"):
            with self.subTest(key=key):
                payload = self.log()
                payload.pop("scan_id")
                payload[key] = "scan-9"
                findings = self.parse_string(payload)
                self.assertTrue(findings[0].unique_id_from_tool.startswith("hiddenlayer-scan-9-"))

    def test_a_bare_sarif_log_is_accepted(self):
        """A log downloaded as-is has no wrapper, and then it carries no scan id either."""
        findings = self.parse_string({"runs": [
            {"tool": {"driver": {"rules": []}},
             "results": [{"ruleId": "RULE_1", "level": "error", "message": {"text": "A finding"}}]}]})
        self.assertEqual(1, len(findings))
        self.assertEqual("hiddenlayer--RULE_1-:0", findings[0].unique_id_from_tool)

    def test_the_log_may_be_wrapped_under_several_keys(self):
        for key in ("sarif", "log", "report"):
            with self.subTest(key=key):
                payload = {"scan_id": "scan-1", key: {"runs": [
                    {"tool": {"driver": {"rules": []}},
                     "results": [{"ruleId": "RULE_1", "level": "error",
                                  "message": {"text": "A finding"}}]}]}}
                self.assertEqual(1, len(self.parse_string(payload)))

    def test_several_runs_all_contribute(self):
        run = {"tool": {"driver": {"rules": []}},
               "results": [{"ruleId": "RULE_1", "level": "error", "message": {"text": "A finding"}}]}
        findings = self.parse_string({"scan_id": "scan-1", "sarif": {"runs": [run, run]}})
        self.assertEqual(2, len(findings))

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string(["not a log"])
        self.assertIn("SARIF", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("runs", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"scan_id": "scan-1", "sarif": {"runs": [
            "not an object",
            None,
            {"tool": {"driver": {"rules": ["not an object", None]}},
             "results": ["not an object", None,
                         {"ruleId": "RULE_1", "level": "error", "message": {"text": "A finding"},
                          "locations": ["not an object", None],
                          "fixes": ["not an object", None]}]},
        ]}})
        self.assertEqual(1, len(findings))
        self.assertEqual("hiddenlayer-scan-1-RULE_1-:0", findings[0].unique_id_from_tool)
        self.assertIsNone(findings[0].mitigation)

    def test_the_file_path_is_in_the_hash(self):
        """One rule firing on two files in a model archive is two findings."""
        self.assertEqual(["title", "severity", "file_path"],
                         HiddenlayerParser().get_dedupe_fields())

    def test_severity_is_always_a_known_value(self):
        for filename in ("hiddenlayer_many_vuln.json", "hiddenlayer_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
