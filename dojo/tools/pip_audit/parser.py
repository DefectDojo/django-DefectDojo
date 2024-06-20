"""Parser for pip-audit."""
import json

from dojo.models import Finding


class PipAuditParser:
    """Represents a file parser capable of ingesting pip-audit results."""

    def get_scan_types(self):
        """Return the type of scan this parser ingests."""
        return ["pip-audit Scan"]

    def get_label_for_scan_types(self, scan_type):
        """Return the friendly name for this parser."""
        return "pip-audit Scan"

    def get_description_for_scan_types(self, scan_type):
        """Return the description for this parser."""
        return "Import pip-audit JSON scan report."

    def requires_file(self, scan_type):
        """Return boolean indicating if parser requires a file to process."""
        return True

    def get_findings(self, scan_file, test):
        """Return the collection of Findings ingested."""
        data = json.load(scan_file)
        # this parser can handle two distinct formats see sample scan files
        return get_file_findings(data, test) if "dependencies" in data else get_legacy_findings(data, test)


def get_file_findings(data, test):
    """Return the findings in the vluns array inside the dependencies key."""
    findings = []
    for dependency in data["dependencies"]:
        item_findings = get_item_findings(dependency, test)
        if item_findings is not None:
            findings.extend(item_findings)
    return findings


def get_legacy_findings(data, test):
    """Return the findings gathered from the vulns element."""
    findings = []
    for item in data:
        item_findings = get_item_findings(item, test)
        if item_findings is not None:
            findings.extend(item_findings)
    return findings


def get_item_findings(item, test):
    """Return list of Findings."""
    findings = []
    vulnerabilities = item.get("vulns", [])
    if vulnerabilities:
        component_name = item["name"]
        component_version = item.get("version")
        for vulnerability in vulnerabilities:
            vuln_id = vulnerability.get("id")
            vuln_fix_versions = vulnerability.get("fix_versions")
            vuln_description = vulnerability.get("description")

            title = (
                f"{vuln_id} in {component_name}:{component_version}"
            )

            description = ""
            description += vuln_description

            mitigation = None
            if vuln_fix_versions:
                mitigation = "Upgrade to version:"
                if len(vuln_fix_versions) == 1:
                    mitigation += f" {vuln_fix_versions[0]}"
                else:
                    for fix_version in vuln_fix_versions:
                        mitigation += f"\n- {fix_version}"

            finding = Finding(
                test=test,
                title=title,
                cwe=1395,
                severity="Medium",
                description=description,
                mitigation=mitigation,
                component_name=component_name,
                component_version=component_version,
                vuln_id_from_tool=vuln_id,
                static_finding=True,
                dynamic_finding=False,
            )
            vulnerability_ids = []
            if vuln_id:
                vulnerability_ids.append(vuln_id)
            if vulnerability_ids:
                finding.unsaved_vulnerability_ids = vulnerability_ids

            findings.append(finding)

    return findings
