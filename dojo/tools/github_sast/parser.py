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
            html_url = vuln.get('html_url')
            rule_id = rule.get("id")
            title = f"{rule.get('description')} ({rule_id})"
            severity = rule.get("security_severity_level", "Info").title()
            active = vuln.get("state") == "open"

            # Build description with context
            desc_lines = []
            if html_url:
                desc_lines.append(f"GitHub Alert: {html_url}")
            if loc.get('path') and loc.get('start_line'):
                desc_lines.append(f"Location: {loc['path']}:{loc['start_line']}")
            msg = inst.get('message', {}).get('text')
            if msg:
                desc_lines.append(f"Message: {msg}")
            if severity:
                desc_lines.append(f"Rule Severity: {severity}")
            if rule.get("full_description"):
                desc_lines.append(f"Description: {rule.get('full_description')}")
            description = "\n".join(desc_lines)

            finding = Finding(
                title=title,
                test=test,
                description=description,
                severity=severity,
                active=active,
                static_finding=True,
                dynamic_finding=False,
                vuln_id_from_tool=rule_id
            )

            # File path & line
            finding.file_path = loc.get('path')
            finding.line = loc.get('start_line')

            if html_url:
                finding.url = html_url
                finding.unsaved_endpoints = [Endpoint.from_uri(html_url)]

            findings.append(finding)
        return findings