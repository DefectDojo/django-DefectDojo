import io
import json
from datetime import UTC, datetime

from dojo.models import Finding, Test
from dojo.tools.elastic_security_cnvm.parser import ElasticSecurityCnvmParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestElasticSecurityCnvmParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("elastic_security_cnvm") / filename
        with path.open(encoding="utf-8") as file:
            return list(ElasticSecurityCnvmParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(ElasticSecurityCnvmParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def document(self, source, document_id="doc-1"):
        return {"hits": {"hits": [{"_id": document_id, "_source": source}]}}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Elastic Security connector's ScanTypeVulnerabilities verbatim.

        Any drift and a customer who uploads an export and also syncs the API gets two
        un-deduplicated copies of every finding.
        """
        parser = ElasticSecurityCnvmParser()
        self.assertEqual(["Elastic Security:CNVM - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "Elastic Security:CNVM - Connectors Import",
            parser.get_label_for_scan_types("Elastic Security:CNVM - Connectors Import"),
        )
        self.assertNotIn("Elastic Security:Posture - Connectors Import", parser.get_scan_types())
        self.assertNotIn("Elastic Security:Detections - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        """
        An export of only posture and detection documents produces nothing here.

        Elastic returns all three kinds from the same search API, so each parser has to claim only its
        own documents - otherwise a posture evaluation would be imported three times under three scan
        types with three different deduplication keys.
        """
        self.assertEqual(0, len(self.parse("elastic_security_cnvm_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("elastic_security_cnvm_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring vulnerabilityFinding in the connector's converter."""
        findings = self.parse("elastic_security_cnvm_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("CVE-2000-0001 - openssl 3.0.2 on web-node-1", finding.title)
        # Elastic's own label wins over the CVSS score, which would say Critical.
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertEqual("openssl", finding.component_name)
        self.assertEqual("3.0.2", finding.component_version)
        self.assertEqual("CVE-2000-0001", finding.vuln_id_from_tool)
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual("doc-cnvm-1", finding.unique_id_from_tool)
        self.assertEqual("https://nvd.example.com/vuln/detail/CVE-2000-0001", finding.references)
        self.assertEqual(datetime(2024, 7, 1, tzinfo=UTC).date(), finding.date)
        self.assertEqual(datetime(2024, 5, 1, tzinfo=UTC).date(), finding.publish_date)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(
            "Upgrade openssl to 3.0.13 or later, then rebuild and redeploy the affected workload image.",
            finding.mitigation,
        )
        self.assertEqual(["aws", "cnvm", "us-east-1", "vulnerability"], finding.unsaved_tags)

        sections = finding.description.split("\n\n")
        self.assertEqual("A memory-safety flaw allows remote code execution.", sections[0])
        self.assertEqual("**Package:** openssl 3.0.2 (deb)", sections[1])
        self.assertEqual("**Resource:** web-node-1 (instance/ec2)", sections[2])
        self.assertEqual("**Host:** web-node-1", sections[3])
        self.assertEqual("**OS:** Ubuntu 22.04.4 LTS", sections[4])
        self.assertEqual("**Cloud:** aws, account example-account, us-east-1", sections[5])
        self.assertEqual("**CVSS:** 9.8 (v3.1)", sections[6])

        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("web-node-1", locations[0].host)

    def test_many_vuln(self):
        """Only CNVM documents, and only those Elastic attached to a CVE."""
        self.assertEqual(5, len(self.parse("elastic_security_cnvm_many_vuln.json")))

    def test_a_document_with_no_cve_id_is_skipped(self):
        findings = self.by_uid("elastic_security_cnvm_many_vuln.json")
        self.assertNotIn("doc-cnvm-not-a-vulnerability", findings)

    def test_an_unrecognised_label_falls_back_to_the_cvss_score(self):
        """
        A CNVM document has a score to fall back on, unlike the other two scan types.

        Elastic's vulnerability severity is free text in practice, so an unknown label is graded from
        the score rather than guessed at from the wording.
        """
        findings = self.by_uid("elastic_security_cnvm_many_vuln.json")
        self.assertEqual("High", findings["doc-cnvm-2"].severity)
        self.assertEqual("Medium", findings["doc-cnvm-3"].severity)

    def test_an_unrecognised_label_with_no_score_is_info(self):
        findings = self.by_uid("elastic_security_cnvm_many_vuln.json")
        self.assertEqual("Info", findings["doc-cnvm-4"].severity)
        self.assertIsNone(findings["doc-cnvm-4"].cvssv3_score)

    def test_severity_labels(self):
        for label, expected in (("critical", "Critical"), ("high", "High"), ("medium", "Medium"),
                                ("low", "Low"), ("informational", "Info"), ("info", "Info"),
                                ("none", "Info"), ("unknown", "Info"), ("CRITICAL", "Critical")):
            with self.subTest(label=label):
                findings = self.parse_string(self.document({
                    "vulnerability": {"id": "CVE-2000-0001", "severity": label},
                }))
                self.assertEqual(expected, findings[0].severity)

    def test_severity_floors_when_the_label_is_unusable(self):
        for base, expected in ((10.0, "Critical"), (9.0, "Critical"), (8.9, "High"), (7.0, "High"),
                               (6.9, "Medium"), (4.0, "Medium"), (3.9, "Low"), (0.1, "Low"),
                               (0, "Info")):
            with self.subTest(base=base):
                findings = self.parse_string(self.document({
                    "vulnerability": {"id": "CVE-2000-0001", "severity": "", "score": {"base": base, "version": "3.1"}},
                }))
                self.assertEqual(expected, findings[0].severity)

    def test_only_a_v3_score_reaches_the_cvssv3_field(self):
        """
        Elastic also reports CVSS v2 bases, which do not belong in a v3 field.

        The score still appears in the description with its version, so nothing is lost.
        """
        findings = self.by_uid("elastic_security_cnvm_many_vuln.json")
        self.assertIsNone(findings["doc-cnvm-3"].cvssv3_score)
        self.assertIn("**CVSS:** 5 (v2.0)", findings["doc-cnvm-3"].description)
        self.assertEqual(7.5, findings["doc-cnvm-2"].cvssv3_score)
        self.assertIn("**CVSS:** 7.5 (v3.0)", findings["doc-cnvm-2"].description)

    def test_a_score_may_arrive_as_a_string(self):
        findings = self.parse_string(self.document({
            "vulnerability": {"id": "CVE-2000-0001", "severity": "", "score": {"base": "8.1", "version": "3.1"}},
        }))
        self.assertEqual("High", findings[0].severity)
        self.assertEqual(8.1, findings[0].cvssv3_score)

    def test_asset_name_falls_back_from_resource_to_pod_to_host(self):
        cases = (
            ({"resource": {"name": "resource"}, "kubernetes": {"pod": {"name": "pod"}},
              "host": {"name": "host"}}, "resource"),
            ({"kubernetes": {"pod": {"name": "pod"}}, "host": {"name": "host"}}, "pod"),
            ({"host": {"name": "host"}}, "host"),
            ({"host": {"hostname": "hostname"}}, "hostname"),
            ({}, ""),
        )
        for source, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(expected, ElasticSecurityCnvmParser().asset_name(source))

    def test_the_endpoint_prefers_the_host_over_the_resource(self):
        """
        The finding is about a machine, so the endpoint is the host identity.

        Only when there is no host does the resource or pod name stand in - a bucket has no hostname
        but is still worth recording.
        """
        findings = self.by_uid("elastic_security_cnvm_many_vuln.json")
        self.assertEqual("web-node-1", self.get_unsaved_locations(findings["doc-cnvm-1"])[0].host)
        self.assertEqual("api-7c9f-abcde", self.get_unsaved_locations(findings["doc-cnvm-4"])[0].host)

    def test_kubernetes_and_cluster_context(self):
        finding = self.by_uid("elastic_security_cnvm_many_vuln.json")["doc-cnvm-4"]
        self.assertIn("**Cluster:** example-cluster, namespace payments", finding.description)
        self.assertIn("cluster:example-cluster", finding.unsaved_tags)

    def test_the_document_id_is_the_identity(self):
        """
        Elasticsearch document ids are stable across syncs, so they are the identity.

        Only a hand-assembled export lacks one; then the asset, CVE and package stand in, which still
        keeps the same CVE on two assets apart.
        """
        findings = self.parse("elastic_security_cnvm_many_vuln.json")
        by_uid = {finding.unique_id_from_tool for finding in findings}
        self.assertIn("doc-cnvm-1", by_uid)
        self.assertIn("batch-node-2:CVE-2000-0005:curl:7.81.0", by_uid)

    def test_mitigation_without_a_fixed_version(self):
        finding = self.by_uid("elastic_security_cnvm_many_vuln.json")["doc-cnvm-2"]
        self.assertIn("No fixed version is published for this CVE yet", finding.mitigation)

    def test_tags_are_sorted_and_deduplicated(self):
        """
        The connector sorts and deduplicates its tags, so a reimport does not look like a change.

        Worth asserting rather than assuming: an unordered tag list is a diff on every sync.
        """
        for finding in self.parse("elastic_security_cnvm_many_vuln.json"):
            with self.subTest(uid=finding.unique_id_from_tool):
                self.assertEqual(sorted(set(finding.unsaved_tags)), finding.unsaved_tags)
                self.assertIn("cnvm", finding.unsaved_tags)
                self.assertIn("vulnerability", finding.unsaved_tags)

    def test_export_shapes(self):
        """A search response, a bare array of documents and a single document are all accepted."""
        doc = {"_id": "doc-1", "_source": {"vulnerability": {"id": "CVE-2000-0001", "severity": "low"}}}
        for payload in ({"hits": {"hits": [doc]}}, [doc], doc, {"hits": [doc]}):
            with self.subTest(shape=type(payload).__name__ + str(list(payload)[:1])):
                findings = self.parse_string(payload)
                self.assertEqual(1, len(findings))
                self.assertEqual("CVE-2000-0001", findings[0].title)

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("Elastic Security", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("hits", str(context.exception))

    def test_malformed_documents_are_skipped(self):
        findings = self.parse_string({"hits": {"hits": [
            "not an object",
            None,
            {"_id": "no-source"},
            {"_id": "doc-1", "_source": {"vulnerability": {"id": "CVE-2000-0001", "severity": "low"}}},
        ]}})
        self.assertEqual(1, len(findings))

    def test_severity_is_always_a_known_value(self):
        for finding in self.parse("elastic_security_cnvm_many_vuln.json"):
            with self.subTest(uid=finding.unique_id_from_tool):
                self.assertIn(finding.severity, Finding.SEVERITIES)
