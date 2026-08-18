import json

from dojo.models import Finding


class KubesecParser:

    """
    Parser for kubesec JSON reports.

    kubesec sorts every rule it applies to a Kubernetes object into one of three buckets:
    ``critical`` for settings that weaken the workload, ``advise`` for hardening it does not
    yet have, and ``passed`` for rules it already satisfies. Each rule carries a point value
    that contributes to the object's overall score.
    """

    # kubesec's own buckets. "passed" is deliberately absent: it lists rules the object
    # already satisfies, which are not findings.
    SEVERITY = {
        "critical": "High",
        "advise": "Low",
    }

    def get_scan_types(self):
        return ["kubesec Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import kubesec reports in JSON format, generated with 'kubesec scan manifest.yaml'."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for report in data or []:
            object_name = report.get("object")
            file_name = report.get("fileName")
            score = report.get("score")
            for bucket, severity in self.SEVERITY.items():
                findings.extend(
                    self._to_finding(rule, bucket, severity, object_name, file_name, score, test)
                    for rule in report.get("scoring", {}).get(bucket, [])
                )
        return findings

    def _to_finding(self, rule, bucket, severity, object_name, file_name, score, test):
        description = []
        if rule.get("reason"):
            description.append(rule["reason"])
        if object_name:
            description.append(f"**Object:** {object_name}")
        description.append(f"**Bucket:** {bucket}")
        if rule.get("selector"):
            description.append(f"**Selector:** `{rule['selector']}`")
        if rule.get("points") is not None:
            description.append(f"**Points:** {rule['points']}")
        if score is not None:
            description.append(f"**Object score:** {score}")

        return Finding(
            title=f"{rule.get('id')}: {rule.get('selector')}",
            test=test,
            description="\n".join(description),
            severity=severity,
            component_name=object_name,
            file_path=file_name,
            vuln_id_from_tool=rule.get("id"),
            static_finding=True,
            dynamic_finding=False,
        )
