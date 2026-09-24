import json
import re

from dateutil import parser

from dojo.models import Finding


class StrixParser:

    """
    Parser for the vulnerabilities.json report of a Strix security run.

    Strix reports one entry per finding, and the set of keys varies by
    finding_class (code findings carry PoC and CVSS breakdowns, dependency
    findings carry package metadata), so every field is optional.
    """

    SEVERITIES = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
        "informational": "Info",
    }

    CWE_PATTERN = re.compile(r"CWE-(\d+)")

    CVSS_METRICS = (
        ("attack_vector", "AV"),
        ("attack_complexity", "AC"),
        ("privileges_required", "PR"),
        ("user_interaction", "UI"),
        ("scope", "S"),
        ("confidentiality", "C"),
        ("integrity", "I"),
        ("availability", "A"),
    )

    DESCRIPTION_SECTIONS = (
        ("Technical analysis", "technical_analysis"),
        ("Evidence", "evidence"),
        ("Assumptions", "assumptions"),
        ("Counter-evidence", "counterevidence"),
        ("Conditions that would change severity", "severity_change_conditions"),
    )

    def get_scan_types(self):
        return ["Strix Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import findings from the vulnerabilities.json report of a Strix security run."

    def get_findings(self, file, test):
        data = json.load(file)
        # The report is a bare array; the wrapped shape is accepted for
        # forward compatibility in case Strix adds report-level metadata.
        if isinstance(data, dict):
            data = data.get("vulnerabilities")
        if not isinstance(data, list):
            msg = f"Strix reports are a JSON array; got a {type(data).__name__}."
            raise TypeError(msg)
        return [self._to_finding(item, test) for item in data if item]

    def _to_finding(self, item, test):
        dependency = item.get("dependency_metadata") or {}
        code_location = (item.get("code_locations") or [{}])[0] or {}

        finding = Finding(
            test=test,
            title=item.get("title"),
            severity=self._severity(item.get("severity")),
            description=self._description(item),
            impact=item.get("impact"),
            steps_to_reproduce=self._steps_to_reproduce(item),
            mitigation=self._mitigation(item),
            cwe=self._cwe(item.get("cwe")),
            vuln_id_from_tool=item.get("id"),
            date=self._date(item.get("timestamp")),
            component_name=dependency.get("package_name"),
            component_version=dependency.get("installed_version"),
            file_path=code_location.get("file"),
            line=code_location.get("start_line"),
            static_finding=item.get("finding_class") != "dynamic",
            dynamic_finding=item.get("finding_class") == "dynamic",
            fix_available=bool(item.get("remediation_steps") or item.get("fix_pr_body")),
        )
        if item.get("cve"):
            finding.unsaved_vulnerability_ids = [item["cve"]]
        cvss = item.get("cvss")
        if isinstance(cvss, int | float):
            finding.cvssv3_score = cvss
        return finding

    def _severity(self, value):
        return self.SEVERITIES.get(str(value).lower(), "Info")

    def _cwe(self, value):
        if not value:
            return None
        match = self.CWE_PATTERN.search(str(value))
        return int(match.group(1)) if match else None

    def _date(self, timestamp):
        if not timestamp:
            return None
        return parser.parse(timestamp)

    def _cvss_vector(self, breakdown):
        if not isinstance(breakdown, dict) or not breakdown:
            return None
        metrics = []
        for key, abbrev in self.CVSS_METRICS:
            value = breakdown.get(key)
            if value is None:
                return None
            metrics.append(f"{abbrev}:{value}")
        return "CVSS:3.1/" + "/".join(metrics)

    def _description(self, item):
        parts = []
        if item.get("description"):
            parts.append(item["description"])
        if item.get("target"):
            parts.append(f"**Target:** {item['target']}")
        if item.get("confidence"):
            parts.append(f"**Confidence:** {item['confidence']}")
        cvss = item.get("cvss")
        if cvss is not None:
            vector = self._cvss_vector(item.get("cvss_breakdown"))
            parts.append(f"**CVSS:** {cvss} ({vector})" if vector else f"**CVSS:** {cvss}")
        for heading, key in self.DESCRIPTION_SECTIONS:
            if item.get(key):
                parts.append(f"## {heading}\n{item[key]}")
        return "\n\n".join(parts)

    @staticmethod
    def _steps_to_reproduce(item):
        # poc_script_code arrives already wrapped in a fenced code block
        parts = [value for value in (item.get("poc_description"), item.get("poc_script_code")) if value]
        return "\n\n".join(parts) or None

    @staticmethod
    def _mitigation(item):
        parts = []
        if item.get("remediation_steps"):
            parts.append(item["remediation_steps"])
        if item.get("fix_effort"):
            parts.append(f"**Fix effort:** {item['fix_effort']}")
        return "\n\n".join(parts) or None
