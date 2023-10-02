import json
from datetime import datetime
from dojo.models import Finding


class AwsSecurityHubParser(object):

    def get_scan_types(self):
        return ["AWS Security Hub Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "AWS Security Hub Scan"

    def get_description_for_scan_types(self, scan_type):
        return "AWS Security Hub exports in JSON format."

    def get_findings(self, filehandle, test):
        tree = json.load(filehandle)
        if not isinstance(tree, dict):
            raise ValueError("Incorrect Security Hub report format")
        return self.get_items(tree, test)

    def get_items(self, tree: dict, test):
        items = {}
        # DefectDojo/django-DefectDojo/issues/2780
        findings = tree.get("Findings", tree.get("findings", None))

        if not findings:
            return list()

        for node in findings:
            item = get_item(node, test)
            key = node["Id"]
            items[key] = item

        return list(items.values())


def get_item(finding: dict, test):
    aws_scanner_type = finding.get("ProductFields", {}).get("aws/securityhub/ProductName", "")
    finding_id = finding.get("Id", "")
    title = finding.get("Title", "")
    severity = finding.get("Severity", {}).get("Label", "INFORMATIONAL").title()
    mitigation = ""
    unsaved_vulnerability_ids = []
    if aws_scanner_type == "Inspector":
        description = f"This is an Inspector Finding\n{finding.get('Description', '')}"
        vulnerabilities = finding.get("Vulnerabilities", [])
        for vulnerability in vulnerabilities:
            # Save the CVE if it is present
            if cve := vulnerability.get("Id"):
                unsaved_vulnerability_ids.append(cve)
            # Add information about the vulnerable packages to the description and mitigation
            vulnerable_packages = vulnerability.get("VulnerablePackages", [])
            for package in vulnerable_packages:
                mitigation += f"- Update {package.get('Name', '')}-{package.get('Version', '')}\n"
                if remediation := package.get("Remediation"):
                    mitigation += f"\t- {remediation}\n"

        if finding.get("ProductFields", {}).get("aws/inspector/FindingStatus", "ACTIVE") == "ACTIVE":
            mitigated = None
            is_Mitigated = False
            active = True
        else:
            is_Mitigated = True
            active = False
            if finding.get("LastObservedAt", None):
                try:
                    mitigated = datetime.strptime(finding.get("LastObservedAt"), "%Y-%m-%dT%H:%M:%S.%fZ")
                except Exception:
                    mitigated = datetime.strptime(finding.get("LastObservedAt"), "%Y-%m-%dT%H:%M:%fZ")
            else:
                mitigated = datetime.utcnow()

    else:
        mitigation = finding.get("Remediation", {}).get("Recommendation", {}).get("Text", "")
        description = "This is a Security Hub Finding \n" + finding.get("Description", "")

        if finding.get("Compliance", {}).get("Status", "PASSED") == "PASSED":
            is_Mitigated = True
            active = False
            if finding.get("LastObservedAt", None):
                try:
                    mitigated = datetime.strptime(finding.get("LastObservedAt"), "%Y-%m-%dT%H:%M:%S.%fZ")
                except Exception:
                    mitigated = datetime.strptime(finding.get("LastObservedAt"), "%Y-%m-%dT%H:%M:%fZ")
            else:
                mitigated = datetime.utcnow()
        else:
            mitigated = None
            is_Mitigated = False
            active = True

    resources = finding.get("Resources", "")
    resource_id = resources[0]["Id"].split(":")[-1]
    references = finding.get("Remediation", {}).get("Recommendation", {}).get("Url")
    false_p = False

    finding = Finding(
        title=f"{title} - Resource: {resource_id}",
        test=test,
        description=description,
        mitigation=mitigation,
        references=references,
        severity=severity,
        impact=f"Resource: {resource_id}",
        active=active,
        verified=False,
        false_p=false_p,
        unique_id_from_tool=finding_id,
        mitigated=mitigated,
        is_mitigated=is_Mitigated,
    )
    # Add the unsaved vulnerability ids
    finding.unsaved_vulnerability_ids = unsaved_vulnerability_ids

    return finding
