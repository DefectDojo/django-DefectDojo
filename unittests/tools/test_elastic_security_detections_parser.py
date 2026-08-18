import io
import json
from datetime import UTC, datetime

from dojo.models import Finding, Test
from dojo.tools.elastic_security_detections.parser import ElasticSecurityDetectionsParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestElasticSecurityDetectionsParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("elastic_security_detections") / filename
        with path.open(encoding="utf-8") as file:
            return list(ElasticSecurityDetectionsParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(ElasticSecurityDetectionsParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def document(self, source, document_id="doc-1"):
        return {"hits": {"hits": [{"_id": document_id, "_source": source}]}}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Elastic Security connector's ScanTypeDetections verbatim.

        Any drift and a customer who uploads an export and also syncs the API gets two
        un-deduplicated copies of every alert.
        """
        parser = ElasticSecurityDetectionsParser()
        self.assertEqual(["Elastic Security:Detections - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "Elastic Security:Detections - Connectors Import",
            parser.get_label_for_scan_types("Elastic Security:Detections - Connectors Import"),
        )
        self.assertNotIn("Elastic Security:CNVM - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        """
        An export of only CNVM and posture documents produces nothing here.

        Elastic returns all three kinds from the same search API, so each parser has to claim only its
        own documents - otherwise one document would be imported three times under three scan types
        with three different deduplication keys.
        """
        self.assertEqual(0, len(self.parse("elastic_security_detections_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("elastic_security_detections_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring detectionFinding in the connector's converter."""
        findings = self.parse("elastic_security_detections_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Malware Detection Alert", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("doc-detection-1", finding.unique_id_from_tool)
        self.assertEqual("rule-uuid-0001", finding.vuln_id_from_tool)
        self.assertEqual(datetime(2024, 7, 2, tzinfo=UTC).date(), finding.date)
        self.assertEqual(
            "https://docs.example.com/rules/malware\nhttps://attack.example.com/techniques/T0000",
            finding.references,
        )
        # A detection is observed activity: neither a static nor a dynamic test found it.
        self.assertFalse(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(
            ["Elastic", "Endpoint Security", "alert", "aws", "detection", "endpoint", "malware",
             "process", "us-east-1"],
            finding.unsaved_tags,
        )

        sections = finding.description.split("\n\n")
        self.assertEqual("malware detected on web-node-1", sections[0])
        self.assertEqual("Detects known malware signatures on an endpoint.", sections[1])
        self.assertEqual("**Message:** Suspicious process started", sections[2])
        self.assertEqual("**Host:** web-node-1", sections[3])
        self.assertEqual("**OS:** Ubuntu 22.04.4 LTS", sections[4])
        self.assertEqual("**Cloud:** aws, account example-account, us-east-1", sections[5])
        self.assertEqual("**Risk score:** 99 (Elastic's 0-100 scale)", sections[6])
        self.assertEqual("**Workflow status in Elastic:** open", sections[7])
        self.assertEqual("**Event category:** process, malware", sections[8])

        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("web-node-1", locations[0].host)

    def test_mitigation_is_a_triage_instruction(self):
        """
        A detection is not a defect with a patch.

        Saying so keeps a triage queue from being read as a remediation backlog, which is why the
        connector writes the same instruction on every detection.
        """
        finding = self.parse("elastic_security_detections_one_vuln.json")[0]
        self.assertIn("Triage this detection in Elastic Security.", finding.mitigation)
        self.assertIn("rather than a fixable defect", finding.mitigation)
        self.assertIn("not shipping a patch", finding.mitigation)

    def test_many_vuln(self):
        """Only alerts with something to say."""
        self.assertEqual(2, len(self.parse("elastic_security_detections_many_vuln.json")))

    def test_an_alert_with_no_rule_name_or_reason_is_skipped(self):
        findings = self.by_uid("elastic_security_detections_many_vuln.json")
        self.assertNotIn("doc-detection-3", findings)

    def test_the_legacy_signal_object_is_accepted(self):
        """
        Current Elastic nests the alert under kibana.alert; the older engine wrote a top-level signal.

        An export taken from an existing index may still carry either, and the connector reads both.
        """
        finding = self.by_uid("elastic_security_detections_many_vuln.json")["doc-detection-2"]
        self.assertEqual("unusual outbound connection from batch-node-2", finding.title)
        self.assertEqual("rule-uuid-0002", finding.vuln_id_from_tool)

    def test_title_falls_back_to_the_alert_reason(self):
        findings = self.parse_string(self.document({
            "kibana": {"alert": {"uuid": "a1", "reason": "something happened", "severity": "low"}},
        }))
        self.assertEqual("something happened", findings[0].title)

    def test_severity_comes_from_the_alert_then_the_rule(self):
        cases = (
            ({"severity": "high", "rule": {"severity": "low"}}, "High"),
            ({"rule": {"severity": "low"}}, "Low"),
            ({"severity": "critical"}, "Critical"),
        )
        for alert, expected in cases:
            with self.subTest(alert=alert):
                findings = self.parse_string(self.document({
                    "kibana": {"alert": {"uuid": "a1", "reason": "an alert", **alert}},
                }))
                self.assertEqual(expected, findings[0].severity)

    def test_an_unrecognised_label_is_medium(self):
        """
        A detection has no score to fall back on, so the connector defaults to Medium.

        Elastic's risk score is a 0-100 scale, not a severity, so it is reported in the description
        rather than being converted into one.
        """
        findings = self.by_uid("elastic_security_detections_many_vuln.json")
        self.assertEqual("Medium", findings["doc-detection-2"].severity)

        for label in ("", "not a label", None):
            with self.subTest(label=label):
                parsed = self.parse_string(self.document({
                    "kibana": {"alert": {"uuid": "a1", "reason": "an alert", "severity": label}},
                }))
                self.assertEqual("Medium", parsed[0].severity)

    def test_risk_score_comes_from_the_alert_then_the_rule(self):
        finding = self.by_uid("elastic_security_detections_many_vuln.json")["doc-detection-2"]
        self.assertIn("**Risk score:** 47 (Elastic's 0-100 scale)", finding.description)

        findings = self.parse_string(self.document({
            "kibana": {"alert": {"uuid": "a1", "reason": "an alert", "risk_score": 21.5,
                                 "rule": {"risk_score": 99}}},
        }))
        self.assertIn("**Risk score:** 21.5 (Elastic's 0-100 scale)", findings[0].description)

    def test_no_risk_score_line_when_there_is_no_score(self):
        findings = self.parse_string(self.document({
            "kibana": {"alert": {"uuid": "a1", "reason": "an alert", "severity": "low"}},
        }))
        self.assertNotIn("**Risk score:**", findings[0].description)

    def test_the_document_id_is_the_identity_and_the_alert_uuid_is_the_fallback(self):
        findings = self.parse_string({"hits": {"hits": [
            {"_source": {"kibana": {"alert": {"uuid": "alert-9", "reason": "an alert"}}}},
        ]}})
        self.assertEqual("alert-9", findings[0].unique_id_from_tool)

    def test_tags_are_sorted_and_deduplicated(self):
        for finding in self.parse("elastic_security_detections_many_vuln.json"):
            with self.subTest(uid=finding.unique_id_from_tool):
                self.assertEqual(sorted(set(finding.unsaved_tags)), finding.unsaved_tags)
                self.assertIn("detection", finding.unsaved_tags)
                self.assertIn("alert", finding.unsaved_tags)

    def test_export_shapes(self):
        doc = {"_id": "doc-1", "_source": {"kibana": {"alert": {"uuid": "a1", "reason": "an alert"}}}}
        for payload in ({"hits": {"hits": [doc]}}, [doc], doc):
            with self.subTest(shape=type(payload).__name__):
                self.assertEqual(1, len(self.parse_string(payload)))

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("Elastic Security", str(context.exception))

    def test_malformed_documents_are_skipped(self):
        findings = self.parse_string({"hits": {"hits": [
            "not an object",
            None,
            {"_id": "no-source"},
            {"_id": "no-alert", "_source": {"message": "just a log line"}},
            {"_id": "doc-1", "_source": {"kibana": {"alert": {"uuid": "a1", "reason": "an alert"}}}},
        ]}})
        self.assertEqual(1, len(findings))

    def test_severity_is_always_a_known_value(self):
        for finding in self.parse("elastic_security_detections_many_vuln.json"):
            with self.subTest(uid=finding.unique_id_from_tool):
                self.assertIn(finding.severity, Finding.SEVERITIES)
