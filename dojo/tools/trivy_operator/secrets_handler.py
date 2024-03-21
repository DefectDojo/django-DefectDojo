from dojo.models import Finding

TRIVY_SEVERITIES = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "UNKNOWN": "Info",
}

SECRET_DESCRIPTION_TEMPLATE = """{title}
**Category:** {category}
**Match:** {match}
"""


class TrivySecretsHandler:
    def handle_secrets(self, service, secrets, test):
        findings = list()
        for secret in secrets:
            secret_title = secret.get("title")
            secret_category = secret.get("category")
            secret_match = secret.get("match", "")
            secret_severity = TRIVY_SEVERITIES[secret.get("severity")]
            secret_rule_id = secret.get("ruleID", "0")
            secret_target = secret.get("target", "")
            secret_references = secret.get("ruleID", "")
            title = f"Secret detected in {secret_target} - {secret_title}"
            secret_description = SECRET_DESCRIPTION_TEMPLATE.format(
                title=secret_title,
                category=secret_category,
                match=secret_match,
            )

            finding = Finding(
                test=test,
                title=title,
                severity=secret_severity,
                references=secret_references,
                description=secret_description,
                file_path=secret_target,
                static_finding=True,
                dynamic_finding=False,
                service=service,
            )
            if secret_rule_id:
                finding.unsaved_vulnerability_ids = [secret_rule_id]
            findings.append(finding)
        return findings
