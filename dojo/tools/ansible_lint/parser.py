import json

from dojo.models import Finding


class AnsibleLintParser:

    """
    Parser for ansible-lint JSON reports.

    ansible-lint emits Code Climate formatted JSON. Its rules cover correctness and idiom as
    well as security-relevant patterns such as unvalidated certificates, world-writable
    permissions and shell use where a module exists, so the rule categories are recorded on
    each Finding to make triage possible.
    """

    # The Code Climate severity scale that ansible-lint emits.
    SEVERITY = {
        "blocker": "Critical",
        "critical": "High",
        "major": "Medium",
        "minor": "Low",
        "info": "Info",
    }

    def get_scan_types(self):
        return ["Ansible Lint Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import ansible-lint reports in JSON format, generated with 'ansible-lint -f json'."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for issue in data or []:
            check_name = issue.get("check_name")
            location = issue.get("location") or {}
            path = location.get("path")
            line = self._line(location)
            categories = issue.get("categories") or []

            description = []
            if issue.get("description"):
                description.append(issue["description"])
            description.append(f"**Rule:** {check_name}")
            if categories:
                description.append(f"**Categories:** {', '.join(categories)}")
            if path:
                description.append(f"**Location:** {path}:{line}" if line else f"**Location:** {path}")

            findings.append(Finding(
                title=f"{check_name}: {issue.get('description')}" if issue.get("description") else check_name,
                test=test,
                description="\n".join(description),
                severity=self.SEVERITY.get(str(issue.get("severity")).lower(), "Low"),
                file_path=path,
                line=line,
                vuln_id_from_tool=check_name,
                # ansible-lint's fingerprint is stable for a given issue in a given file.
                unique_id_from_tool=issue.get("fingerprint"),
                references=issue.get("url") or None,
                static_finding=True,
                dynamic_finding=False,
            ))
        return findings

    def _line(self, location):
        """ansible-lint reports either a bare line or a begin/end position block."""
        positions = location.get("positions") or {}
        begin = positions.get("begin")
        if isinstance(begin, dict):
            return begin.get("line")
        if isinstance(begin, int):
            return begin
        lines = location.get("lines")
        return lines.get("begin") if isinstance(lines, dict) else None
