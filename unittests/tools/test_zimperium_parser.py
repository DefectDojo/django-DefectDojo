import io
import json
from datetime import UTC, date, datetime

from dojo.models import Finding, Test
from dojo.tools.hiddenlayer.parser import SarifConnectorFindings
from dojo.tools.zimperium.parser import ZimperiumParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestZimperiumParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("zimperium") / filename
        with path.open(encoding="utf-8") as file:
            return list(ZimperiumParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(ZimperiumParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def report(self, result=None, rule=None, **context):
        payload = {"assessment": {"id": "assess-1", "appVersion": "1.0.0"},
                   "app": {"name": "Generic Mobile App", "platform": "android"},
                   "sarif": {"runs": [{"tool": {"driver": {"rules": [rule] if rule else []}},
                                       "results": [result or {"ruleId": "RULE_1", "level": "error",
                                                              "message": {"text": "A finding"}}]}]}}
        payload.update(context)
        return payload

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Zimperium connector's ScanTypeName verbatim.

        Note it does NOT follow the "<Vendor> - Connectors Import" pattern the other connector scan
        types use, so it cannot be derived - it has to be copied.
        """
        parser = ZimperiumParser()
        self.assertEqual(["Zimperium zScan"], parser.get_scan_types())
        self.assertEqual("Zimperium zScan", parser.get_label_for_scan_types("Zimperium zScan"))
        self.assertNotIn("Zimperium - Connectors Import", parser.get_scan_types())

    def test_the_sarif_mapping_is_shared_with_the_other_sarif_connectors(self):
        """
        On the Go side these connectors call one shared utility, parameterised per vendor.

        Extending the same mixin here is what keeps them from drifting apart - the shipped invicti
        parser extends netsparker the same way. Only the prefix, the static flag and the decoration
        differ.
        """
        self.assertTrue(issubclass(ZimperiumParser, SarifConnectorFindings))
        self.assertEqual("zimperium", ZimperiumParser.tool_prefix)
        self.assertTrue(ZimperiumParser.is_static)

    def test_the_shared_mixin_is_not_itself_a_parser(self):
        """
        dojo/tools/factory.py registers the class whose lowercased name matches its module.

        "SarifConnectorFindings" matches no module, so it stays invisible - as netsparker's shared
        base does.
        """
        self.assertFalse(hasattr(SarifConnectorFindings, "get_scan_types"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("zimperium_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("zimperium_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """The shared SARIF mapping plus Zimperium's own app and build decoration."""
        findings = self.parse("zimperium_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Cleartext traffic is permitted for all domains", finding.title)
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("zimperium-assess-0001-ZS_CLEARTEXT_TRAFFIC-"
                         "res/xml/network_security_config.xml:3", finding.unique_id_from_tool)
        self.assertEqual("ZS_CLEARTEXT_TRAFFIC", finding.vuln_id_from_tool)
        self.assertEqual(7.4, finding.cvssv3_score)
        self.assertEqual(319, finding.cwe)
        self.assertEqual("res/xml/network_security_config.xml", finding.file_path)
        self.assertEqual(3, finding.line)
        self.assertEqual("https://example.com/rules/cleartext-traffic", finding.references)
        self.assertEqual("Set cleartextTrafficPermitted to false.", finding.mitigation)
        self.assertTrue(finding.active)
        self.assertFalse(finding.false_p)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        # The app, its build version and the upload date all come from the decoration.
        self.assertEqual("Generic Mobile App", finding.component_name)
        self.assertEqual("3.2.0", finding.component_version)
        self.assertEqual(date(2024, 6, 2), finding.date)
        # The platform is appended AFTER the SARIF tags.
        self.assertEqual(["cwe-319", "network", "mobile", "android"], finding.unsaved_tags)

    def test_many_vuln(self):
        """Four results, but the "pass" result is never imported."""
        self.assertEqual(3, len(self.parse("zimperium_many_vuln.json")))

    def test_the_app_and_build_context_decorates_every_finding(self):
        """
        A SARIF document says nothing about which app or build it came from.

        Two builds of one app land in the same product, and without the version there is no telling
        them apart - so the decoration is what makes a mobile finding actionable.
        """
        for finding in self.parse("zimperium_many_vuln.json"):
            with self.subTest(uid=finding.unique_id_from_tool):
                self.assertEqual("Generic Mobile App", finding.component_name)
                self.assertEqual("4.0.1", finding.component_version)
                self.assertEqual(date(2024, 6, 5), finding.date)
                self.assertIn("ios", finding.unsaved_tags)

    def test_the_identity_is_namespaced_by_the_assessment(self):
        """
        One assessment is one scan of one build.

        The same rule firing in two builds is two findings, which is what lets a reader see that a
        problem survived a release.
        """
        first = self.parse_string(self.report(assessment={"id": "assess-a", "appVersion": "1.0.0"}))
        second = self.parse_string(self.report(assessment={"id": "assess-b", "appVersion": "1.0.1"}))
        self.assertEqual("zimperium-assess-a-RULE_1-:0", first[0].unique_id_from_tool)
        self.assertEqual("zimperium-assess-b-RULE_1-:0", second[0].unique_id_from_tool)

    def test_the_assessment_id_may_be_spelled_three_ways_or_sit_at_the_top_level(self):
        for key in ("assessment_id", "assessmentId", "id"):
            with self.subTest(key=key):
                payload = self.report()
                payload.pop("assessment")
                payload[key] = "assess-9"
                findings = self.parse_string(payload)
                self.assertTrue(findings[0].unique_id_from_tool.startswith("zimperium-assess-9-"))

    def test_a_bare_sarif_report_is_accepted(self):
        """
        A report downloaded as-is has no envelope, so it carries no app or build context either.

        The findings still import; they simply have no component or version.
        """
        findings = self.parse_string({"runs": [
            {"tool": {"driver": {"rules": []}},
             "results": [{"ruleId": "RULE_1", "level": "error", "message": {"text": "A finding"}}]}]})
        self.assertEqual(1, len(findings))
        self.assertEqual("zimperium--RULE_1-:0", findings[0].unique_id_from_tool)
        self.assertIsNone(findings[0].component_name)
        self.assertIsNone(findings[0].component_version)
        self.assertEqual(datetime.now(tz=UTC).date(), findings[0].date)

    def test_the_context_may_be_stated_at_the_top_level(self):
        findings = self.parse_string({
            "id": "assess-3", "name": "Generic Mobile App", "appVersion": "2.0.0",
            "platform": "android", "buildUploadedAt": "2024-07-01T00:00:00Z",
            "sarif": {"runs": [{"tool": {"driver": {"rules": []}},
                                "results": [{"ruleId": "RULE_1", "level": "error",
                                             "message": {"text": "A finding"}}]}]}})
        finding = findings[0]
        self.assertEqual("zimperium-assess-3-RULE_1-:0", finding.unique_id_from_tool)
        self.assertEqual("Generic Mobile App", finding.component_name)
        self.assertEqual("2.0.0", finding.component_version)
        self.assertEqual(date(2024, 7, 1), finding.date)
        self.assertIn("android", finding.unsaved_tags)

    def test_a_suppressed_result_is_inactive_and_a_false_positive(self):
        """Shared behaviour: SARIF suppression is a reviewer saying this one does not count."""
        finding = self.by_uid("zimperium_many_vuln.json")[
            "zimperium-assess-0002-ZS_WEAK_CRYPTO-Payload/GenericApp/Crypto.m:88"]
        self.assertFalse(finding.active)
        self.assertTrue(finding.false_p)

    def test_a_result_that_is_not_a_failure_is_skipped(self):
        findings = self.by_uid("zimperium_many_vuln.json")
        for finding in findings.values():
            self.assertNotIn("Never imported", finding.title)

    def test_a_security_severity_word_grades_but_scores_nothing(self):
        finding = self.by_uid("zimperium_many_vuln.json")[
            "zimperium-assess-0002-ZS_WEAK_CRYPTO-Payload/GenericApp/Crypto.m:88"]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual(0.0, finding.cvssv3_score)

    def test_a_note_level_result_with_no_score_is_info(self):
        finding = self.by_uid("zimperium_many_vuln.json")["zimperium-assess-0002-ZS_DEBUG_SYMBOLS-:0"]
        self.assertEqual("Info", finding.severity)

    def test_the_cwe_taxonomy_prefix_is_stripped_from_tags(self):
        finding = self.by_uid("zimperium_many_vuln.json")[
            "zimperium-assess-0002-ZS_HARDCODED_SECRET-Payload/GenericApp/Config.plist:12"]
        self.assertEqual(["cwe-798", "secrets", "mobile", "ios"], finding.unsaved_tags)
        self.assertEqual(798, finding.cwe)

    def test_the_decoration_does_not_overwrite_what_sarif_already_said(self):
        """Each field is only filled when the shared mapping left it empty, as the connector does."""
        findings = self.parse_string(self.report())
        self.assertEqual("Generic Mobile App", findings[0].component_name)

    def test_an_unparseable_upload_date_leaves_the_date_alone(self):
        findings = self.parse_string(self.report(
            assessment={"id": "assess-1", "appVersion": "1.0.0",
                        "buildUploadedAt": "not a timestamp"}))
        self.assertEqual(datetime.now(tz=UTC).date(), findings[0].date)

    def test_no_platform_appends_no_tag(self):
        findings = self.parse_string(self.report(app={"name": "Generic Mobile App"}))
        self.assertEqual([], findings[0].unsaved_tags)

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string(["not a report"])
        self.assertIn("Zimperium", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("runs", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"assessment": {"id": "assess-1"}, "sarif": {"runs": [
            "not an object",
            None,
            {"tool": {"driver": {"rules": ["not an object", None]}},
             "results": ["not an object", None,
                         {"ruleId": "RULE_1", "level": "error", "message": {"text": "A finding"}}]},
        ]}})
        self.assertEqual(1, len(findings))
        self.assertEqual("zimperium-assess-1-RULE_1-:0", findings[0].unique_id_from_tool)

    def test_the_file_path_and_the_rule_are_both_in_the_hash(self):
        """One rule firing on two files in an app bundle is two findings."""
        self.assertEqual(["title", "severity", "file_path", "vuln_id_from_tool"],
                         ZimperiumParser().get_dedupe_fields())

    def test_severity_is_always_a_known_value(self):
        for filename in ("zimperium_many_vuln.json", "zimperium_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
