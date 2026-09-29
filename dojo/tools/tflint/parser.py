import json

from dojo.models import Finding


class TFLintParser:

    """
    Parser for TFLint JSON reports.

    TFLint reports issues against Terraform source, each carrying the rule that raised it
    and the range in the file it applies to. Rules come from the core ruleset and from
    provider plugins, and both use the same three-level severity scale.
    """

    # TFLint's own severity scale, as emitted in rule.severity.
    SEVERITY = {
        "error": "High",
        "warning": "Medium",
        "notice": "Info",
    }

    def get_scan_types(self):
        return ["TFLint Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import TFLint reports in JSON format, generated with 'tflint --format json'."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for issue in data.get("issues", []):
            rule = issue.get("rule", {})
            issue_range = issue.get("range", {})
            filename = issue_range.get("filename")
            line = issue_range.get("start", {}).get("line")

            description = [issue.get("message", "")]
            if filename:
                location = f"{filename}:{line}" if line else filename
                description.append(f"**Location:** {location}")
            if issue.get("fixable"):
                description.append("**Fixable:** TFLint can fix this issue with --fix.")
            description.extend(
                f"**Called from:** {caller}" for caller in issue.get("callers", [])
            )

            finding = Finding(
                title=f"{rule.get('name')}: {issue.get('message')}",
                test=test,
                description="\n".join(part for part in description if part),
                severity=self.SEVERITY.get(rule.get("severity"), "Medium"),
                file_path=filename,
                line=line,
                vuln_id_from_tool=rule.get("name"),
                # TFLint plugins leave the link empty for rules that have no published page.
                references=rule.get("link") or None,
                static_finding=True,
                dynamic_finding=False,
            )
            findings.append(finding)
        return findings
