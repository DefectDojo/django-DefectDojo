
from dojo.location.feature import locations_enabled
from dojo.models import Finding
from dojo.tools.locations import LocationData

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
"""  # noqa: S105


class TrivySecretsHandler:
    def handle_secrets(self, labels, secrets, test, image=None):
        findings = []
        resource_namespace = labels.get("trivy-operator.resource.namespace", "")
        resource_kind = labels.get("trivy-operator.resource.kind", "")
        resource_name = labels.get("trivy-operator.resource.name", "")
        container_name = labels.get("trivy-operator.container.name", "")
        # resource_name is excluded from service on purpose: for Pods owned by a
        # ReplicaSet it holds the ReplicaSet's generated name, which changes on
        # every deploy. Since close_old_findings matches on an exact service
        # string, including it here would make service change on every redeploy
        # and permanently prevent old findings from ever being closed.
        service = f"{resource_namespace}/{resource_kind}"
        if container_name:
            service = f"{service}/{container_name}"
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
            secret_description += "\n**container.name:** " + container_name
            secret_description += "\n**resource.kind:** " + resource_kind
            secret_description += "\n**resource.name:** " + resource_name
            secret_description += "\n**resource.namespace:** " + resource_namespace
            secret_description += "\n**ruleID:** " + secret_rule_id
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
                fix_available=True,
            )
            if locations_enabled() and secret_target:
                finding.unsaved_locations.append(
                    LocationData.code(file_path=secret_target),
                )
            if image is not None:
                finding.unsaved_locations.append(image)
            if resource_namespace:
                finding.unsaved_tags = [resource_namespace]
            findings.append(finding)
        return findings
