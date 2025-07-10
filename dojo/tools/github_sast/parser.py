import json
from dojo.models import Finding, Endpoint

class GithubSASTParser:
    def get_scan_types(self):
        return ["Github SAST Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "GitHub SAST report file can be imported in JSON format."

    def get_findings(self, filename, test):
        data = json.load(filename)
        if not isinstance(data, list):
            raise ValueError("Invalid SAST report format, expected a JSON list of alerts.")

        findings = []
        for vuln in data:
            rule = vuln.get("rule", {})
            inst = vuln.get("most_recent_instance", {})
            loc = inst.get("location", {})

            title = rule.get("id")
            severity = rule.get("security_severity_level", "Info").title()
            active = vuln.get("state") == "open"

            desc = rule.get("description", "") + "\n"
            desc += f"**Location:** {loc.get('path')}:{loc.get('start_line')}\n"
            desc += f"**Message:** {inst.get('message', {}).get('text')}\n"
            desc += f"**Rule Severity:** {rule.get('severity')}\n"

            finding = Finding(
                title=title,
                test=test,
                description=desc,
                severity=severity,
                active=active,
                static_finding=True,
                dynamic_finding=False,
                unique_id_from_tool=f"{vuln.get('rule', {}).get('id')}|{vuln.get('url')}|{loc.get('start_line')}",
            )

            # file path & line
            finding.file_path = loc.get('path')
            finding.line = loc.get('start_line')

            # endpoint
            html_url = vuln.get('html_url')
            if html_url:
                finding.unsaved_endpoints = [Endpoint.from_uri(html_url)]

            findings.append(finding)
        return findings