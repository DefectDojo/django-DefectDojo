import json

from dojo.models import Finding


class ModelScanParser:

    """
    Parser for ModelScan JSON reports.

    ModelScan inspects serialized machine-learning models for operators capable of
    executing code at load time. Its findings describe an unsafe operator reached from
    a module, not a CVE, so no vulnerability id is attached.
    """

    # ModelScan's own severity scale, from its default settings.
    SEVERITY = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
    }

    def get_scan_types(self):
        return ["ModelScan Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import ModelScan reports in JSON format, generated with 'modelscan -p <path> -r json -o report.json'."

    def get_findings(self, file, test):
        data = json.load(file)
        scanner_version = data.get("summary", {}).get("modelscan_version")
        findings = []
        for issue in data.get("issues", []):
            operator = issue.get("operator")
            module = issue.get("module")
            source = issue.get("source")

            description = []
            if issue.get("description"):
                description.append(issue["description"])
            if module and operator:
                description.append(f"**Operator:** `{module}.{operator}`")
            if source:
                description.append(f"**Model file:** {source}")
            if issue.get("scanner"):
                description.append(f"**Scanner:** {issue['scanner']}")
            if scanner_version:
                description.append(f"**ModelScan version:** {scanner_version}")

            finding = Finding(
                title=f"Unsafe operator '{operator}' from module '{module}'",
                test=test,
                description="\n".join(description),
                severity=self.SEVERITY.get(str(issue.get("severity")).upper(), "Medium"),
                mitigation=(
                    "Load this model only from a trusted source, or re-serialize it in a format "
                    "that cannot carry executable code, such as safetensors."
                ),
                file_path=source,
                component_name=source,
                vuln_id_from_tool=f"{module}.{operator}" if module and operator else operator,
                static_finding=True,
                dynamic_finding=False,
            )
            findings.append(finding)
        return findings
