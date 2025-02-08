from dojo.models import Finding
from dojo.tools.trivy_operator.uniform_vulnid import UniformTrivyVulnID

TRIVY_SEVERITIES = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "UNKNOWN": "Info",
}


class TrivyComplianceHandler:
    def handle_compliance(self, benchmarkreport, test):
        findings = []
        for result in benchmarkreport.get("results"):
            for check in result.get("checks"):
                description = "**detailReport description:** " + benchmarkreport.get("description") + "\n"
                if check.get("success") is False:
                    result_description = result.get("description", "")
                    result_id = result.get("id", "")
                    result_name = result.get("name", "")
                    result_severity = result.get("severity", "")
                    check_category = check.get("category", "")
                    check_checkID = check.get("checkID", "")
                    check_description = check.get("description", "")
                    check_messages = ""
                    for message in check.get("messages", []):
                        check_messages += message + "\n"
                    check_remediation = check.get("remediation", "")
                    check_severity = check.get("severity", "")
                    check_target = check.get("target", "")
                    check_title = check.get("title", "")
                    if check_severity == "":
                        severity = TRIVY_SEVERITIES[check_severity]
                    else:
                        severity = TRIVY_SEVERITIES[result_severity]
                    description += "**result description:** " + result_description + "\n"
                    description += "**result id:** " + result_id + "\n"
                    description += "**result name:** " + result_name + "\n"
                    description += "**checkcategory:** " + check_category + "\n"
                    description += "**checkcheckID:** " + check_checkID + "\n"
                    description += "**checkdescription:** " + check_description + "\n"
                    description += "**checkmessages:** " + check_messages + "\n"
                    description += "**checktarget:** " + check_target + "\n"
                    description += "**checktitle:** " + check_title + "\n"
                    title = f"{result_id} {check_checkID} {check_target}"
                    finding = Finding(
                        test=test,
                        title=title,
                        severity=severity,
                        mitigation=check_remediation,
                        description=description,
                        static_finding=False,
                        dynamic_finding=True,
                    )
                    if check_checkID:
                        finding.unsaved_vulnerability_ids = [UniformTrivyVulnID().return_uniformed_vulnid(check_checkID)]
                    findings.append(finding)
        return findings
