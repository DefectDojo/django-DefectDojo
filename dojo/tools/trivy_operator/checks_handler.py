from dojo.models import Finding

TRIVY_SEVERITIES = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "UNKNOWN": "Info",
}


class TrivyChecksHandler:
    def handle_checks(self, service, checks, test):
        findings = list()
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
            if check_id:
                finding.unsaved_vulnerability_ids = [check_id]
            findings.append(finding)
        return findings
