import json

from dojo.models import Finding


class CfripperParser:

    """
    Parser for CFRipper JSON reports.

    CFRipper audits CloudFormation templates for security misconfiguration — wildcard IAM,
    privilege escalation, public resources — which is distinct from the syntax linting that
    cfn-lint and cfn-nag perform. Each failure carries CFRipper's own risk value.
    """

    SEVERITY = {
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }

    def get_scan_types(self):
        return ["CFRipper Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import CFRipper reports in JSON format, generated with 'cfripper <template> --format json'."

    def get_findings(self, file, test):
        data = json.load(file)
        return [self._to_finding(failure, test) for failure in data.get("failures", [])]

    def _to_finding(self, failure, test):
        rule = failure.get("rule")
        reason = failure.get("reason")
        resources = failure.get("resource_ids") or []
        resource = resources[0] if resources else None

        description = [reason] if reason else []
        description.append(f"**Rule:** {rule}")
        if failure.get("granularity"):
            description.append(f"**Granularity:** {failure['granularity']}")
        if resources:
            description.append(f"**Resources:** {', '.join(resources)}")
        if failure.get("resource_types"):
            description.append(f"**Resource types:** {', '.join(failure['resource_types'])}")
        if failure.get("rule_mode"):
            description.append(f"**Rule mode:** {failure['rule_mode']}")
        if failure.get("actions"):
            description.append(f"**Actions:** {', '.join(failure['actions'])}")

        return Finding(
            title=f"{rule}: {resource}" if resource else rule,
            test=test,
            description="\n".join(description),
            severity=self.SEVERITY.get(str(failure.get("risk_value")).lower(), "Medium"),
            component_name=resource,
            vuln_id_from_tool=rule,
            static_finding=True,
            dynamic_finding=False,
        )
