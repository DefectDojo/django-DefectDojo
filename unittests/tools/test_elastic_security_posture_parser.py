import io
import json
from datetime import UTC, datetime

from dojo.models import Finding, Test
from dojo.tools.elastic_security_posture.parser import ElasticSecurityPostureParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestElasticSecurityPostureParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("elastic_security_posture") / filename
        with path.open(encoding="utf-8") as file:
            return list(ElasticSecurityPostureParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(ElasticSecurityPostureParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def document(self, source, document_id="doc-1"):
        return {"hits": {"hits": [{"_id": document_id, "_source": source}]}}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Elastic Security connector's ScanTypePosture verbatim.

        Any drift and a customer who uploads an export and also syncs the API gets two
        un-deduplicated copies of every failing rule.
        """
        parser = ElasticSecurityPostureParser()
        self.assertEqual(["Elastic Security:Posture - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "Elastic Security:Posture - Connectors Import",
            parser.get_label_for_scan_types("Elastic Security:Posture - Connectors Import"),
        )
        self.assertNotIn("Elastic Security:CNVM - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        """
        An export of only CNVM and detection documents produces nothing here.

        Elastic returns all three kinds from the same search API, so each parser has to claim only its
        own documents - otherwise one document would be imported three times under three scan types
        with three different deduplication keys.
        """
        self.assertEqual(0, len(self.parse("elastic_security_posture_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("elastic_security_posture_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring postureFinding in the connector's converter."""
        findings = self.parse("elastic_security_posture_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Ensure the audit log is enabled", finding.title)
        self.assertEqual("Medium", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("doc-posture-1", finding.unique_id_from_tool)
        self.assertEqual("rule-0001", finding.vuln_id_from_tool)
        self.assertEqual("CIS Kubernetes V1.23", finding.component_name)
        self.assertEqual("v1.0.1", finding.component_version)
        self.assertEqual("Enable the audit log in the cluster configuration.", finding.mitigation)
        self.assertEqual("https://docs.example.com/cis/3.2.1", finding.references)
        self.assertEqual(datetime(2024, 7, 1, tzinfo=UTC).date(), finding.date)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(
            ["CIS", "CIS 3.2.1", "CIS Kubernetes V1.23", "Kubernetes", "cluster:example-cluster",
             "compliance", "configuration", "kspm", "posture"],
            finding.unsaved_tags,
        )

        sections = finding.description.split("\n\n")
        self.assertEqual("An audit log records administrative actions for later review.", sections[0])
        self.assertEqual("Checks the API server's audit-log configuration.", sections[1])
        self.assertEqual("This benchmark rule **failed** evaluation.", sections[2])
        self.assertEqual("**Benchmark:** CIS Kubernetes V1.23 v1.0.1, rule 3.2.1", sections[3])
        self.assertEqual("**Section:** Logging", sections[4])
        self.assertEqual("**Host:** control-plane-1", sections[5])
        self.assertEqual("**OS:** Ubuntu 22.04.4 LTS", sections[6])
        self.assertEqual("**Cluster:** example-cluster, namespace kube-system", sections[7])
        self.assertEqual("**Impact of remediation:** Log volume increases.", sections[8])

        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("control-plane-1", locations[0].host)

    def test_many_vuln(self):
        """Only failing, named posture rules."""
        self.assertEqual(2, len(self.parse("elastic_security_posture_many_vuln.json")))

    def test_only_failed_evaluations_are_imported(self):
        """
        Elastic writes a document for every evaluation, passed or failed.

        A passing rule is not a finding, and a rule with no name has nothing to report.
        """
        findings = self.by_uid("elastic_security_posture_many_vuln.json")
        self.assertIn("doc-posture-1", findings)
        self.assertIn("doc-posture-2", findings)
        self.assertNotIn("doc-posture-passed", findings)
        self.assertNotIn("doc-posture-unnamed", findings)

    def test_evaluation_is_read_case_insensitively(self):
        """The second document reports "FAILED"."""
        self.assertIn("doc-posture-2", self.by_uid("elastic_security_posture_many_vuln.json"))

    def test_severity_labels(self):
        for label, expected in (("critical", "Critical"), ("high", "High"), ("medium", "Medium"),
                                ("low", "Low"), ("informational", "Info"), ("unknown", "Info")):
            with self.subTest(label=label):
                findings = self.parse_string(self.document({
                    "rule": {"id": "r1", "name": "A rule", "severity": label},
                    "result": {"evaluation": "failed"},
                }))
                self.assertEqual(expected, findings[0].severity)

    def test_an_unrecognised_label_is_medium(self):
        """
        A posture document has no score to fall back on, so the connector defaults to Medium.

        Info would be wrong - a failing benchmark rule is a real finding whatever Elastic called its
        severity.
        """
        findings = self.by_uid("elastic_security_posture_many_vuln.json")
        self.assertEqual("Medium", findings["doc-posture-2"].severity)

        for label in ("", "not a label", None):
            with self.subTest(label=label):
                parsed = self.parse_string(self.document({
                    "rule": {"id": "r1", "name": "A rule", "severity": label},
                    "result": {"evaluation": "failed"},
                }))
                self.assertEqual("Medium", parsed[0].severity)

    def test_a_repeated_rationale_is_not_printed_twice(self):
        """
        Elastic often copies the rationale into the description.

        Printing the same paragraph twice reads as a rendering error, so the connector drops the
        duplicate and so does this parser.
        """
        finding = self.by_uid("elastic_security_posture_many_vuln.json")["doc-posture-2"]
        sections = finding.description.split("\n\n")
        self.assertEqual("The same text as the rationale.", sections[0])
        self.assertEqual("This benchmark rule **failed** evaluation.", sections[1])
        self.assertEqual(1, finding.description.count("The same text as the rationale."))

    def test_rule_id_falls_back_to_the_benchmark_numbering(self):
        """
        The rule id is what this scan type's deduplication hash keys on.

        Elastic's cloud benchmarks do not always carry one, so the benchmark's own numbering stands in
        before the rule name does.
        """
        findings = self.by_uid("elastic_security_posture_many_vuln.json")
        self.assertEqual("cis_aws:2.1.1", findings["doc-posture-2"].vuln_id_from_tool)

        by_name = self.parse_string(self.document({
            "rule": {"name": "A rule with nothing else", "severity": "low"},
            "result": {"evaluation": "failed"},
        }))
        self.assertEqual("A rule with nothing else", by_name[0].vuln_id_from_tool)

    def test_a_cloud_resource_is_the_asset_when_there_is_no_host(self):
        finding = self.by_uid("elastic_security_posture_many_vuln.json")["doc-posture-2"]
        self.assertIn("**Resource:** example-bucket (s3/bucket)", finding.description)
        self.assertIn("**Cloud:** aws, account example-account, us-east-1", finding.description)
        self.assertEqual("example-bucket", self.get_unsaved_locations(finding)[0].host)

    def test_the_benchmark_is_the_component(self):
        findings = self.by_uid("elastic_security_posture_many_vuln.json")
        self.assertEqual("CIS AWS Foundations", findings["doc-posture-2"].component_name)
        self.assertEqual("v1.5.0", findings["doc-posture-2"].component_version)

    def test_a_rule_with_no_benchmark(self):
        findings = self.parse_string(self.document({
            "rule": {"id": "r1", "name": "A rule", "severity": "high"},
            "result": {"evaluation": "failed"},
        }))
        self.assertIsNone(findings[0].component_name)
        self.assertNotIn("**Benchmark:**", findings[0].description)
        self.assertEqual(["compliance", "configuration", "posture"], findings[0].unsaved_tags)

    def test_the_document_id_is_the_identity(self):
        """
        Elasticsearch document ids are stable across syncs, so they are the identity.

        Only a hand-assembled export lacks one; then the asset and the rule stand in, which keeps the
        same rule failing on two assets apart.
        """
        findings = self.parse_string({"hits": {"hits": [
            {"_source": {"rule": {"id": "r1", "name": "A rule"}, "result": {"evaluation": "failed"},
                         "host": {"name": "host-a"}}},
            {"_source": {"rule": {"id": "r1", "name": "A rule"}, "result": {"evaluation": "failed"},
                         "host": {"name": "host-b"}}},
        ]}})
        self.assertEqual(
            {"host-a:r1:A rule", "host-b:r1:A rule"},
            {finding.unique_id_from_tool for finding in findings},
        )

    def test_tags_are_sorted_and_deduplicated(self):
        for finding in self.parse("elastic_security_posture_many_vuln.json"):
            with self.subTest(uid=finding.unique_id_from_tool):
                self.assertEqual(sorted(set(finding.unsaved_tags)), finding.unsaved_tags)
                self.assertIn("posture", finding.unsaved_tags)
                self.assertIn("compliance", finding.unsaved_tags)

    def test_export_shapes(self):
        doc = {"_id": "doc-1", "_source": {"rule": {"id": "r1", "name": "A rule", "severity": "low"},
                                           "result": {"evaluation": "failed"}}}
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
            {"_id": "doc-1", "_source": {"rule": {"id": "r1", "name": "A rule"},
                                         "result": {"evaluation": "failed"}}},
        ]}})
        self.assertEqual(1, len(findings))

    def test_a_document_with_no_result_block_is_skipped(self):
        """No evaluation means Elastic has not scored the rule against this asset."""
        self.assertEqual(0, len(self.parse_string(self.document({
            "rule": {"id": "r1", "name": "A rule", "severity": "high"},
        }))))
