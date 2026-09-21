import json

from dojo.models import Finding


class GixyParser:

    """
    Parser for Gixy JSON reports.

    Gixy analyses nginx configuration for security misconfiguration — HTTP splitting, host
    header issues, referrer validation, version disclosure. Each finding carries Gixy's own
    severity and the plugin that raised it.
    """

    SEVERITY = {
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }

    def get_scan_types(self):
        return ["Gixy Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Gixy nginx configuration reports in JSON format, generated with 'gixy -f json <config>'."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for issue in data or []:
            plugin = issue.get("plugin")
            line = issue.get("line")

            description = []
            if issue.get("summary"):
                description.append(issue["summary"])
            if issue.get("reason"):
                description.append(f"**Reason:** {issue['reason']}")
            description.append(f"**Plugin:** {plugin}")
            if issue.get("config"):
                description.append(f"**Config:**\n```\n{issue['config'].strip()}\n```")

            findings.append(Finding(
                title=f"{plugin}: {issue.get('summary')}" if issue.get("summary") else plugin,
                test=test,
                description="\n".join(description),
                severity=self.SEVERITY.get(str(issue.get("severity")).lower(), "Medium"),
                # Gixy reports the config path in both 'file' and 'path'; 'file' is the on-disk
                # location, 'path' can be a virtual include location.
                file_path=issue.get("file"),
                line=line,
                vuln_id_from_tool=plugin,
                mitigation=issue.get("description") or None,
                references=issue.get("reference") or None,
                static_finding=True,
                dynamic_finding=False,
            ))
        return findings
