from dojo.models import Finding

TRIVY_SEVERITIES = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "UNKNOWN": "Info",
}


class TrivyClusterComplianceHandler:
    def handle_clustercompliance(self, controls, clustercompliance, test):
        findings = []
        for result in clustercompliance.get("controlCheck"):
            if int(result.get("totalFail", 0)) > 0:
                description = ""
                result_id = result.get("id", "")
                vulnerabilityids = []
                for control in controls:
                    if control.get("id") == result_id:
                        vulnids = control.get("checks", [])
                        vulnerabilityids.extend(vulnid.get("id") for vulnid in vulnids)
                        description += "**description:** " + control.get("description") + "\n"
                result_name = result.get("name", "")
                result_severity = result.get("severity", "")
                result_totalfail = str(result.get("totalFail", ""))
                severity = TRIVY_SEVERITIES[result_severity]
                description += "**id:** " + result_id + "\n"
                description += "**name:** " + result_name + "\n"
                description += "**totalfail:** " + result_totalfail + "\n"
                title = "TrivyClusterCompliance " + result_id + " totalFail: " + result_totalfail
                finding = Finding(
                    test=test,
                    title=title,
                    description=description,
                    severity=severity,
                    static_finding=False,
                    dynamic_finding=True,
                )
                if vulnerabilityids != []:
                    finding.unsaved_vulnerability_ids = vulnerabilityids
                findings.append(finding)
        return findings
