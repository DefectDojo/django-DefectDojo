import json

from dojo.models import Finding

# The shared document walk and ECS asset rendering live on the CNVM parser's module, the same way the
# shipped Invicti parser extends the Netsparker one. Elastic returns all three scan types from the same
# _search API with the same asset objects.
from dojo.tools.elastic_security_cnvm.parser import ElasticSecurityDocuments

# A detection has no score to fall back on, so an unrecognised severity label is Medium.
UNRECOGNISED_SEVERITY = "Medium"

# Verbatim from the connector. A detection is not a defect with a patch, and saying so keeps a triage
# queue from being read as a remediation backlog.
DETECTION_MITIGATION = (
    "Triage this detection in Elastic Security. Detections describe observed activity rather than a "
    "fixable defect, so closing it means completing an investigation, not shipping a patch."
)


class ElasticSecurityDetectionsParser(ElasticSecurityDocuments):

    """
    Parses an Elastic Security export, importing detection-engine alerts.

    Mirrors the detection half of pkg/tools/elasticsecurity/connector/converter field for field so a
    file import and an API sync deduplicate against each other instead of producing two copies of
    everything. CNVM vulnerabilities and posture evaluations in the same export are separate scan types
    - see the Elastic Security CNVM and Posture parsers - because Elastic models them as different
    kinds of data and the connector imports each behind its own toggle.

    Detections are event-stream data rather than remediable weaknesses, which is why they are imported
    neither as static nor as dynamic findings and carry a triage instruction instead of a fix.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeDetections.
        return ["Elastic Security:Detections - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Elastic Security:Detections - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import an Elastic Security export (JSON) and report its detection-engine alerts. Matches "
            "the scan type used by the Elastic Security connector so file and API findings "
            "deduplicate. CNVM and posture documents in the same export are imported by the Elastic "
            "Security CNVM and Posture parsers."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Elastic Security Detections Parser.

        Mirrors the connector's detectionFinding:
        - title: the detection rule's name, falling back to the alert's own reason.
        - severity: the alert's label, then the rule's; an unrecognised one is Medium.
        - description: the reason, the rule description, the message, the ECS asset context, the risk
          score, the workflow status and the event category.
        - mitigation: a triage instruction, not a fix.
        - unique_id_from_tool: the Elasticsearch document id, falling back to the alert uuid.
        - vuln_id_from_tool: the rule uuid, which is what the deduplication hash keys on.
        """
        return [
            "title",
            "severity",
            "date",
            "description",
            "mitigation",
            "references",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "tags",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Elastic Security Detections Parser.

        Copied from the Elastic Security detections block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields.
        """
        return ["title", "severity", "vuln_id_from_tool"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        findings = []
        for doc in self.documents(data):
            source = self.source(doc)
            if source is None:
                continue
            alert = self.alert(source)
            if alert is None:
                # Not a detection document.
                continue
            if not self.title(alert):
                # An alert with neither a rule name nor a reason says nothing.
                continue
            findings.append(self.build_finding(doc, source, alert, test))
        return findings

    def alert(self, source):
        """
        The alert, from either place Elastic puts one.

        Current Elastic nests it under kibana.alert; the older detection engine wrote a top-level
        signal object, and an export from an existing index may still carry either.
        """
        alert = self.block(self.block(source, "kibana"), "alert")
        if alert:
            return alert
        signal = source.get("signal")
        return signal if isinstance(signal, dict) else None

    def build_finding(self, doc, source, alert, test):
        rule = self.block(alert, "rule")
        severity, recognised = self.severity_from_string(self.severity_label(alert, rule))

        finding = Finding(
            test=test,
            title=self.title(alert),
            severity=severity if recognised else UNRECOGNISED_SEVERITY,
            description=self.describe(source, alert, rule),
            mitigation=DETECTION_MITIGATION,
            unique_id_from_tool=self.unique_id(doc, alert),
            # A detection is observed activity: neither a static nor a dynamic test found it.
            static_finding=False,
            dynamic_finding=False,
        )
        finding.unsaved_tags = self.tags(source, alert, rule)

        if rule:
            finding.vuln_id_from_tool = str(rule.get("uuid") or "").strip() or None
            finding.references = "\n".join(self.strings(rule.get("references")))
        if date := self.date_only(source.get("@timestamp")):
            finding.date = date

        self.attach_asset(finding, source)
        return finding

    def title(self, alert):
        """The rule's name, falling back to the alert's own reason."""
        rule = self.block(alert, "rule")
        if name := str(rule.get("name") or "").strip():
            return name
        return str(alert.get("reason") or "").strip()

    def severity_label(self, alert, rule):
        """The alert's severity, then the rule's."""
        if severity := str(alert.get("severity") or "").strip():
            return severity
        return str(rule.get("severity") or "").strip()

    def unique_id(self, doc, alert):
        if document_id := str(doc.get("_id") or "").strip():
            return document_id
        return str(alert.get("uuid") or "").strip() or None

    def risk_score(self, alert, rule):
        """Elastic's 0-100 risk score, from the alert or from the rule that raised it."""
        score = self.flex_float(alert.get("risk_score"))
        if score > 0:
            return score
        return self.flex_float(rule.get("risk_score"))

    def describe(self, source, alert, rule):
        parts = []
        if reason := str(alert.get("reason") or "").strip():
            parts.append(reason)
        if description := str(rule.get("description") or "").strip():
            parts.append(description)
        if message := str(source.get("message") or "").strip():
            parts.append(f"**Message:** {message}")

        parts.extend(self.asset_lines(source))

        if score := self.risk_score(alert, rule):
            parts.append(f"**Risk score:** {self.render_number(score)} (Elastic's 0-100 scale)")
        if state := str(alert.get("workflow_status") or "").strip():
            parts.append(f"**Workflow status in Elastic:** {state}")
        if categories := self.strings(self.block(source, "event").get("category")):
            parts.append("**Event category:** " + ", ".join(categories))
        return "\n\n".join(parts)

    def tags(self, source, alert, rule):
        tags = ["detection", "alert"]
        tags.extend(self.strings(rule.get("tags")))
        event = self.block(source, "event")
        tags.extend(self.strings(event.get("category")))
        tags.append(str(event.get("module") or ""))
        tags.extend(self.cloud_tags(source))
        return self.dedupe(tags)
