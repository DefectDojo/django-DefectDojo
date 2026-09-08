import json

from dojo.models import Finding

# The shared document walk and ECS asset rendering live on the CNVM parser's module, the same way the
# shipped Invicti parser extends the Netsparker one. Elastic returns all three scan types from the same
# _search API with the same asset objects.
from dojo.tools.elastic_security_cnvm.parser import ElasticSecurityDocuments

# The result.evaluation value the connector imports. A passed evaluation is not a finding.
EVALUATION_FAILED = "failed"

# A posture document has no score to fall back on, so an unrecognised severity label is Medium.
UNRECOGNISED_SEVERITY = "Medium"


class ElasticSecurityPostureParser(ElasticSecurityDocuments):

    """
    Parses an Elastic Security export, importing the benchmark rules that failed evaluation.

    Mirrors the posture half of pkg/tools/elasticsecurity/connector/converter field for field so a file
    import and an API sync deduplicate against each other instead of producing two copies of
    everything. CNVM vulnerabilities and detection alerts in the same export are separate scan types -
    see the Elastic Security CNVM and Detections parsers - because Elastic models them as different
    kinds of data and the connector imports each behind its own toggle.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypePosture.
        return ["Elastic Security:Posture - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Elastic Security:Posture - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import an Elastic Security export (JSON) and report the cloud and Kubernetes benchmark "
            "rules that failed. Matches the scan type used by the Elastic Security connector so file "
            "and API findings deduplicate. CNVM and detection documents in the same export are "
            "imported by the Elastic Security CNVM and Detections parsers."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Elastic Security Posture Parser.

        Mirrors the connector's postureFinding:
        - title: the rule name.
        - severity: Elastic's own label; an unrecognised one is Medium.
        - description: the rationale, the description, the benchmark, the section, the ECS asset
          context and the impact of remediating.
        - mitigation: the rule's own remediation text.
        - component_name / component_version: the benchmark the rule belongs to.
        - unique_id_from_tool: the Elasticsearch document id.
        - vuln_id_from_tool: the rule id, which is what the deduplication hash keys on.
        """
        return [
            "title",
            "severity",
            "date",
            "description",
            "mitigation",
            "references",
            "component_name",
            "component_version",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "tags",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Elastic Security Posture Parser.

        Copied from the Elastic Security posture block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. Note it hashes vuln_id_from_tool -
        the rule - rather than a component, because a benchmark rule is not about a package.
        """
        return ["title", "severity", "vuln_id_from_tool"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        findings = []
        for doc in self.documents(data):
            source = self.source(doc)
            if source is None:
                continue
            rule = self.block(source, "rule")
            if not rule or not self.failed(source):
                # Not a posture document, or a rule that passed.
                continue
            if not str(rule.get("name") or "").strip():
                # Without a name there is nothing to report.
                continue
            findings.append(self.build_finding(doc, source, rule, test))
        return findings

    def failed(self, source):
        """Elastic writes "failed" or "passed"; only a failure is a finding."""
        evaluation = self.block(source, "result").get("evaluation")
        return str(evaluation or "").strip().lower() == EVALUATION_FAILED

    def build_finding(self, doc, source, rule, test):
        benchmark = self.block(rule, "benchmark")
        severity, recognised = self.severity_from_string(rule.get("severity"))

        finding = Finding(
            test=test,
            title=str(rule["name"]).strip(),
            severity=severity if recognised else UNRECOGNISED_SEVERITY,
            description=self.describe(source, rule, benchmark),
            mitigation=str(rule.get("remediation") or "").strip(),
            references=str(rule.get("references") or "").strip(),
            unique_id_from_tool=self.unique_id(doc, source, rule),
            vuln_id_from_tool=self.rule_id(rule, benchmark),
            # A benchmark rule is evaluated against configuration, not against a running request.
            static_finding=True,
            dynamic_finding=False,
        )
        finding.unsaved_tags = self.tags(source, rule, benchmark)

        if name := str(benchmark.get("name") or "").strip():
            finding.component_name = name
            finding.component_version = str(benchmark.get("version") or "").strip() or None
        if date := self.date_only(source.get("@timestamp")):
            finding.date = date

        self.attach_asset(finding, source)
        return finding

    def unique_id(self, doc, source, rule):
        """
        The Elasticsearch document id, which is stable across syncs.

        Only a hand-assembled export lacks one; then the asset and the rule stand in, which keeps the
        same rule failing on two assets as two findings.
        """
        if document_id := str(doc.get("_id") or "").strip():
            return document_id
        return ":".join([
            self.asset_name(source),
            str(rule.get("id") or ""),
            str(rule.get("name") or ""),
        ])

    def rule_id(self, rule, benchmark):
        """The rule id, then the benchmark's own numbering, then the rule name."""
        if identifier := str(rule.get("id") or "").strip():
            return identifier
        if rule_number := str(benchmark.get("rule_number") or "").strip():
            return str(benchmark.get("id") or "") + ":" + rule_number
        return str(rule.get("name") or "").strip()

    def describe(self, source, rule, benchmark):
        parts = []
        rationale = str(rule.get("rationale") or "").strip()
        if rationale:
            parts.append(rationale)
        description = str(rule.get("description") or "").strip()
        # Elastic often repeats the rationale as the description; printing it twice reads as an error.
        if description and description != rationale:
            parts.append(description)

        parts.append("This benchmark rule **failed** evaluation.")

        if name := str(benchmark.get("name") or "").strip():
            line = f"**Benchmark:** {name}"
            if version := str(benchmark.get("version") or "").strip():
                line += f" {version}"
            if rule_number := str(benchmark.get("rule_number") or "").strip():
                line += f", rule {rule_number}"
            parts.append(line)

        if section := str(rule.get("section") or "").strip():
            parts.append(f"**Section:** {section}")

        parts.extend(self.asset_lines(source))

        if impact := str(rule.get("impact") or "").strip():
            parts.append(f"**Impact of remediation:** {impact}")
        return "\n\n".join(parts)

    def tags(self, source, rule, benchmark):
        tags = ["posture", "compliance", "configuration"]
        if benchmark:
            tags.extend([
                str(benchmark.get("name") or ""),
                str(benchmark.get("posture_type") or ""),
            ])
        tags.extend(self.strings(rule.get("tags")))
        tags.extend(self.cloud_tags(source))
        return self.dedupe(tags)
