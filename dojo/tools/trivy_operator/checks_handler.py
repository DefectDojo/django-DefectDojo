from dojo.models import Finding
from dojo.tools.trivy_operator.uniform_vulnid import UniformTrivyVulnID

TRIVY_SEVERITIES = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "UNKNOWN": "Info",
}


class TrivyChecksHandler:
    def handle_checks(self, labels, checks, test):
        findings = []
        resource_namespace = labels.get("trivy-operator.resource.namespace", "")
        resource_kind = labels.get("trivy-operator.resource.kind", "")
        resource_name = labels.get("trivy-operator.resource.name", "")
        container_name = labels.get("trivy-operator.container.name", "")
        service = f"{resource_namespace}/{resource_kind}/{resource_name}"
        if container_name != "":
            service = f"{service}/{container_name}"
        for check in checks:
            check_title = check.get("title")
            check_severity = TRIVY_SEVERITIES[check.get("severity")]
            check_id = check.get("checkID", "0")
            check_references = ""
            if check_id != 0:
                check_references = (
                    "https://avd.aquasec.com/misconfig/kubernetes/"
                    + check_id.lower()
                )
            check_description = check.get("description", "")
            check_description += "\n**container.name:** " + container_name
            check_description += "\n**resource.kind:** " + resource_kind
            check_description += "\n**resource.name:** " + resource_name
            check_description += "\n**resource.namespace:** " + resource_namespace
            title = f"{check_id} - {check_title}"
            finding = Finding(
                test=test,
                title=title,
                severity=check_severity,
                references=check_references,
                description=check_description,
                static_finding=True,
                dynamic_finding=False,
                service=service,
            )
            if resource_namespace != "":
                finding.tags = resource_namespace
            if check_id:
                finding.unsaved_vulnerability_ids = [UniformTrivyVulnID().return_uniformed_vulnid(check_id)]
            findings.append(finding)
        return findings
