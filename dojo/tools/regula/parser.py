import json

from dojo.models import Finding


class RegulaParser:

    """
    Parser for Regula JSON reports.

    Regula evaluates infrastructure as code against OPA policies. It reports every rule it
    evaluated against every resource, passing and failing alike, so only the failures become
    Findings.
    """

    SEVERITY = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "informational": "Info",
    }

    def get_scan_types(self):
        return ["Regula Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Regula reports in JSON format, generated with 'regula run --format json'."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for result in data.get("rule_results", []):
            # Regula reports PASS results alongside failures; only failures are findings.
            if str(result.get("rule_result")).upper() != "FAIL":
                continue
            findings.append(self._to_finding(result, test))
        return findings

    def _to_finding(self, result, test):
        rule_id = result.get("rule_id")
        rule_name = result.get("rule_name")
        resource_id = result.get("resource_id")
        filepath = result.get("filepath")
        line = self._line(result)

        description = []
        if result.get("rule_description"):
            description.append(result["rule_description"])
        description.extend([
            f"**Rule:** {rule_name} ({rule_id})",
            f"**Resource:** {resource_id}",
        ])
        if result.get("resource_type"):
            description.append(f"**Resource type:** {result['resource_type']}")
        if result.get("provider"):
            description.append(f"**Provider:** {result['provider']}")
        if result.get("input_type"):
            description.append(f"**Input type:** {result['input_type']}")
        if result.get("rule_message"):
            description.append(f"**Message:** {result['rule_message']}")
        description.extend(f"**Control:** {control}" for control in result.get("controls") or [])

        return Finding(
            title=result.get("rule_summary") or rule_name,
            test=test,
            description="\n".join(description),
            severity=self.SEVERITY.get(str(result.get("rule_severity")).lower(), "Medium"),
            file_path=filepath,
            line=line,
            component_name=resource_id,
            vuln_id_from_tool=rule_id,
            references=result.get("rule_remediation_doc") or None,
            static_finding=True,
            dynamic_finding=False,
        )

    def _line(self, result):
        """Regula reports the location as a list, one entry per contributing expression."""
        locations = result.get("source_location") or []
        if locations and isinstance(locations[0], dict):
            return locations[0].get("line")
        return None
