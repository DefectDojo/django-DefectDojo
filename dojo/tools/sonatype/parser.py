import json

from dojo.models import Finding
from dojo.tools.sonatype.identifier import ComponentIdentifier


class SonatypeParser:
    # This parser does not deal with licenses information.

    def get_scan_types(self):
        return ["Sonatype Application Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Sonatype Application Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Can be imported in JSON format"

    def get_findings(self, json_output, test):
        sonatype_report = json.load(json_output)
        findings = []
        if "components" in sonatype_report:
            components = sonatype_report["components"]

            for component in components:
                if component["securityData"] is None or len(component["securityData"]["securityIssues"]) < 1:
                    continue

                for security_issue in component["securityData"]["securityIssues"]:
                    finding = get_finding(security_issue, component, test)
                    findings.append(finding)

        return findings


def get_finding(security_issue, component, test):

    severity = get_severity(security_issue)
    threat_category = security_issue.get("threatCategory", "CVSS vector not provided. ").title()
    status = security_issue["status"]
    reference = security_issue["url"]

    identifier = ComponentIdentifier(component)
    title = f"{security_issue['reference']} - {identifier.component_id}"

    finding_description = f"Hash {component['hash']}\n\n"
    finding_description += identifier.component_id
    finding_description = finding_description.strip()

    finding = Finding(
        test=test,
        title=title,
        description=finding_description,
        component_name=identifier.component_name,
        component_version=identifier.component_version,
        severity=severity,
        mitigation=status,
        references=reference,
        impact=threat_category,
        static_finding=True,
    )
    if "cwe" in security_issue:
        finding.cwe = security_issue["cwe"]

    if "cvssVector" in security_issue:
        finding.cvssv3 = security_issue["cvssVector"]

    if "pathnames" in component:
        finding.file_path = " ".join(component["pathnames"])[:1000]

    if security_issue.get("source") == "cve":
        vulnerability_id = security_issue.get("reference")
        finding.unsaved_vulnerability_ids = [vulnerability_id]

    return finding


def get_severity(vulnerability):
    if vulnerability["severity"] <= 3.9:
        return "Low"
    if vulnerability["severity"] <= 6.9:
        return "Medium"
    if vulnerability["severity"] <= 8.9:
        return "High"
    return "Critical"
