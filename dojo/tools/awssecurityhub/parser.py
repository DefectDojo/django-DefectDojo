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

        if not isinstance(findings, list):
            raise ValueError("Incorrect Security Hub report format")

        for node in findings:
            item = get_item(node, test)
            key = node["Id"]
            if not isinstance(key, str):
                raise ValueError("Incorrect Security Hub report format")
            items[key] = item

        return list(items.values())


def get_item(finding: dict, test):
    aws_scanner_type = finding.get("ProductFields", {}).get("aws/securityhub/ProductName", "")
    finding_id = finding.get("Id", "")
    title = finding.get("Title", "")
    severity = finding.get("Severity", {}).get("Label", "INFORMATIONAL").title()
    mitigation = ""
    impact = []
    references = []
    unsaved_vulnerability_ids = []
    if aws_scanner_type == "Inspector":
        description = f"This is an Inspector Finding\n{finding.get('Description', '')}"
        vulnerabilities = finding.get("Vulnerabilities", [])
        for vulnerability in vulnerabilities:
            # Save the CVE if it is present
            if cve := vulnerability.get("Id"):
                unsaved_vulnerability_ids.append(cve)
            for alias in vulnerability.get("RelatedVulnerabilities", []):
                if alias != cve:
                    unsaved_vulnerability_ids.append(alias)
            # Add information about the vulnerable packages to the description and mitigation
            vulnerable_packages = vulnerability.get("VulnerablePackages", [])
            for package in vulnerable_packages:
                mitigation += f"- Update {package.get('Name', '')}-{package.get('Version', '')}\n"
                if remediation := package.get("Remediation"):
                    mitigation += f"\t- {remediation}\n"
            if vendor := vulnerability.get("Vendor"):
                if vendor_url := vendor.get("Url"):
                    references.append(vendor_url)

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

    title_suffix = ""
    for resource in finding.get("Resources", []):
        if resource.get("Type") == "AwsEcrContainerImage":
            details = resource.get("Details", {}).get("AwsEcrContainerImage")
            arn = resource.get("Id")
            if details:
                impact.append(f"Image ARN: {arn}")
                impact.append(f"Registry: {details.get('RegistryId')}")
                impact.append(f"Repository: {details.get('RepositoryName')}")
                impact.append(f"Image digest: {details.get('ImageDigest')}")
            title_suffix = f" - Image: {arn.split('/', 1)[1]}"  # repo-name/sha256:digest
        else:  # generic implementation
            resource_id = resource["Id"].split(":")[-1]
            impact.append(f"Resource: {resource_id}")
            title_suffix = f" - Resource: {resource_id}"

    if remediation_rec_url := finding.get("Remediation", {}).get("Recommendation", {}).get("Url"):
        references.append(remediation_rec_url)
    false_p = False

    result = Finding(
        title=f"{title}{title_suffix}",
        test=test,
        description=description,
        mitigation=mitigation,
        references="\n".join(references),
        severity=severity,
        impact="\n".join(impact),
        active=active,
        verified=False,
        false_p=false_p,
        unique_id_from_tool=finding_id,
        mitigated=mitigated,
        is_mitigated=is_Mitigated,
        static_finding=True,
        dynamic_finding=False,
    )
    # Add the unsaved vulnerability ids
    result.unsaved_vulnerability_ids = unsaved_vulnerability_ids

    return result
