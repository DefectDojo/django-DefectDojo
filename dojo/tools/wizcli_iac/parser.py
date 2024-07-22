import json
from dojo.models import Finding

class WizcliIaCParser:
    def get_scan_types(self):
        return ["Wizcli IaC Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Wizcli IaC Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Wizcli IaC Scan results in JSON file format."

    def parse_rule_matches(self, rule_matches, test):
        findings = []
        if rule_matches:
            for rule_match in rule_matches:
                rule = rule_match.get("rule", {})
                rule_id = rule.get("id", "N/A")
                rule_name = rule.get("name", "N/A")
                severity = rule_match.get("severity", "low").lower().capitalize()

                matches = rule_match.get("matches", [])
                if matches:
                    for match in matches:
                        resource_name = match.get("resourceName", "N/A")
                        file_name = match.get("fileName", "N/A")
                        line_number = match.get("lineNumber", "N/A")
                        match_content = match.get("matchContent", "N/A")
                        expected = match.get("expected", "N/A")
                        found = match.get("found", "N/A")
                        file_type = match.get("fileType", "N/A")

                        description = (
                            f"**Rule ID**: {rule_id}\n"
                            f"**Rule Name**: {rule_name}\n"
                            f"**Resource Name**: {resource_name}\n"
                            f"**File Name**: {file_name}\n"
                            f"**Line Number**: {line_number}\n"
                            f"**Match Content**: {match_content}\n"
                            f"**Expected**: {expected}\n"
                            f"**Found**: {found}\n"
                            f"**File Type**: {file_type}\n"
                        )

                        finding = Finding(
                            title=f"{rule_name} - {resource_name}",
                            description=description,
                            severity=severity,
                            file_path=file_name,
                            line=line_number,
                            static_finding=True,
                            dynamic_finding=False,
                            mitigation=None,
                            test=test,
                        )
                        findings.append(finding)
        return findings

    def parse_secrets(self, secrets, test):
        findings = []
        if secrets:
            for secret in secrets:
                secret_id = secret.get("id", "N/A")
                description = secret.get("description", "N/A")
                severity = "High"
                file_name = secret.get("path", "N/A")
                line_number = secret.get("lineNumber", "N/A")
                match_content = secret.get("type", "N/A")

                description = (
                    f"**Secret ID**: {secret_id}\n"
                    f"**Description**: {description}\n"
                    f"**File Name**: {file_name}\n"
                    f"**Line Number**: {line_number}\n"
                    f"**Match Content**: {match_content}\n"
                )

                finding = Finding(
                    title=f"Secret: {description}",
                    description=description,
                    severity=severity,
                    file_path=file_name,
                    line=line_number,
                    static_finding=True,
                    dynamic_finding=False,
                    mitigation=None,
                    test=test,
                )
                findings.append(finding)
        return findings

    def get_findings(self, filename, test):
        scan_data = filename.read()
        try:
            data = json.loads(scan_data.decode("utf-8"))
        except Exception:
            data = json.loads(scan_data)
        findings = []
        results = data.get("result", {})

        rule_matches = results.get("ruleMatches", None)
        if rule_matches:
            findings.extend(self.parse_rule_matches(rule_matches, test))

        secrets = results.get("secrets", None)
        if secrets:
            findings.extend(self.parse_secrets(secrets, test))

        return findings