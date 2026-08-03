import json

from dojo.models import Finding

# Regula reports every rule it evaluated, passes included - a small Terraform file readily produces
# more PASS results than FAIL ones. Only a failed rule is a finding; a PASS is the tool confirming
# there is nothing wrong, and importing those would fill DefectDojo with items nobody can action.
# WAIVED means the operator has already excluded the rule on purpose, so that is not a finding
# either.
FAILED_RESULT = "FAIL"

# Regula grades its own rules, so these are the tool's severities and not this parser's invention.
SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Info",
}
# Regula emits "Unknown" for a rule with no severity set, including custom rules. Those are real
# policy failures, so they land at Medium rather than Info.
DEFAULT_SEVERITY = "Medium"


class RegulaParser:

    """
    Parses a Regula infrastructure-as-code policy report.

    Regula evaluates Terraform, CloudFormation and Kubernetes manifests against compliance rules and
    reports a PASS or FAIL per rule per resource. Only the failures are imported - see
    FAILED_RESULT.
    """

    def get_scan_types(self):
        return ["Regula Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Regula Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Regula infrastructure-as-code policy report "
            "(`regula run <path> --format json`). Only failed rules are imported; passing and "
            "waived rules are not findings."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Regula Parser.

        - title: the rule summary, e.g. "S3 buckets should not be publicly readable".
        - severity: Regula's own Critical/High/Medium/Low/Informational grading.
        - description: the rule description, the offending resource, and the compliance controls.
        - component_name: the resource type, e.g. aws_s3_bucket.
        - file_path / line: the template and line Regula points at.
        - references: Regula's remediation document for the rule.
        - vuln_id_from_tool: the Regula rule id, e.g. FG_R00277.
        - unique_id_from_tool: rule id and resource id together, which is what identifies one
          failure - the same rule commonly fails against several resources in one template.
        """
        return [
            "title",
            "severity",
            "description",
            "component_name",
            "file_path",
            "line",
            "references",
            "vuln_id_from_tool",
            "unique_id_from_tool",
            "tags",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Regula Parser.

        The rule/resource pair carried as unique_id_from_tool is the primary identity. These hash
        fields are the fallback, and deliberately exclude line: moving a resource within a template
        is not a new finding.
        """
        return ["title", "file_path", "component_name"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        results = self.extract_results(data)

        findings = {}
        for result in results:
            if not isinstance(result, dict):
                continue
            if (result.get("rule_result") or "").strip().upper() != FAILED_RESULT:
                continue
            finding = self.build_finding(result, test)
            # The same rule and resource can appear more than once when several compliance
            # families map to it; the pair is the identity, so keep the first.
            findings.setdefault(finding.unique_id_from_tool, finding)
        return list(findings.values())

    def extract_results(self, data):
        if isinstance(data, dict) and isinstance(data.get("rule_results"), list):
            return data["rule_results"]
        if isinstance(data, list):
            return data
        msg = (
            "A Regula report is a JSON object with a 'rule_results' list; got "
            f"{type(data).__name__}. Produce one with `regula run <path> --format json`."
        )
        raise TypeError(msg)

    def build_finding(self, result, test):
        rule_id = result.get("rule_id") or ""
        resource_id = result.get("resource_id") or ""
        resource_type = result.get("resource_type") or ""
        location = (result.get("source_location") or [{}])[0] or {}
        path = result.get("filepath") or location.get("path")

        finding = Finding(
            test=test,
            title=result.get("rule_summary") or result.get("rule_name") or rule_id or "Policy failure",
            severity=self.severity(result),
            description=self.describe(result, resource_id, resource_type),
            component_name=resource_type or None,
            file_path=path or None,
            line=location.get("line") or None,
            references=result.get("rule_remediation_doc") or None,
            vuln_id_from_tool=rule_id or None,
            unique_id_from_tool=f"{rule_id}:{resource_id}" if rule_id or resource_id else None,
            # Regula reads templates, never a running system.
            static_finding=True,
            dynamic_finding=False,
        )
        finding.unsaved_tags = self.tags(result, resource_type)
        return finding

    def severity(self, result):
        return SEVERITY_MAP.get((result.get("rule_severity") or "").strip().lower(), DEFAULT_SEVERITY)

    def describe(self, result, resource_id, resource_type):
        lines = []
        if result.get("rule_description"):
            lines.append(result["rule_description"].strip())
        # rule_message is usually empty, but carries rule-specific detail when set.
        if result.get("rule_message"):
            lines.append(f"\n**Message:** {result['rule_message']}")

        details = [
            ("Rule", result.get("rule_name")),
            ("Rule ID", result.get("rule_id")),
            ("Resource", resource_id),
            ("Resource type", resource_type),
            ("Provider", result.get("provider")),
            ("Input type", result.get("input_type")),
        ]
        rendered = [f"**{label}:** {value}" for label, value in details if value]
        if rendered:
            lines.append("\n" + "\n".join(rendered))

        controls = result.get("controls") or []
        if controls:
            lines.append("\n**Compliance controls:** " + ", ".join(str(c) for c in controls))
        return "\n".join(lines)

    def tags(self, result, resource_type):
        tags = []
        if result.get("provider"):
            tags.append(f"provider:{result['provider']}")
        if resource_type:
            tags.append(f"resource:{resource_type}")
        if result.get("input_type"):
            tags.append(f"input:{result['input_type']}")
        # The compliance families a rule belongs to, e.g. CIS-AWS_v1.4.0.
        tags.extend(f"family:{family}" for family in (result.get("families") or []))
        return tags
