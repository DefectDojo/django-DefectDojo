import json

from dojo.location.feature import locations_enabled
from dojo.models import Finding
from dojo.tools.locations import LocationData
from dojo.tools.sonatype.identifier import ComponentIdentifier
from dojo.utils import parse_cvss_data

SONATYPE_FORMAT_TO_PURL = {
    "pypi": "pypi", "rpm": "rpm", "gem": "gem", "golang": "golang",
    "conan": "conan", "conda": "conda", "bower": "npm", "composer": "composer",
    "cran": "cran", "cargo": "cargo", "cocoapods": "cocoapods",
    "swift": "swift", "maven": "maven", "npm": "npm", "nuget": "nuget",
}


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
                security_issues = (component.get("securityData") or {}).get("securityIssues") or []
                if not security_issues:
                    if locations_enabled() and (dep := get_dependency_from_component(component)):
                        test.unsaved_metadata.append(dep)
                else:
                    for security_issue in security_issues:
                        finding = get_finding(security_issue, component, test)
                        findings.append(finding)

        return findings


def get_dependency_from_component(component):
    if purl := component.get("packageUrl"):
        return LocationData.dependency(purl=purl)
    # "componentIdentifier" is null when Sonatype could not identify the component
    component_identifier = component.get("componentIdentifier") or {}
    comp_format = component_identifier.get("format")
    coords = component_identifier.get("coordinates")
    if comp_format and coords:
        purl_type = SONATYPE_FORMAT_TO_PURL.get(comp_format.lower())
        if purl_type:
            version = coords.get("version", "")
            namespace = ""

            if comp_format == "maven":
                name = coords.get("artifactId", "")
                namespace = coords.get("groupId")
            elif comp_format in {"npm", "nuget"}:
                name = coords.get("packageId", "")
            else:
                name = coords.get("name", "")

            if name:
                return LocationData.dependency(
                    purl_type=purl_type,
                    namespace=namespace,
                    name=name,
                    version=version,
                )
    return None


def get_finding(security_issue, component, test):

    severity = get_severity(security_issue)
    threat_category = security_issue.get("threatCategory", "CVSS vector not provided. ").title()
    status = security_issue.get("status")
    reference = security_issue.get("url")

    identifier = ComponentIdentifier(component)
    title = f"{security_issue.get('reference', '')} - {identifier.component_id}"

    finding_description = f"Hash {component['hash']}\n\n" if component.get("hash") else ""
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
        cvss_data = parse_cvss_data(security_issue["cvssVector"])
        if cvss_data:
            finding.cvssv3 = cvss_data.get("cvssv3")
            finding.cvssv3_score = cvss_data.get("cvssv3_score")

    if component.get("pathnames") is not None:
        finding.file_path = " ".join(component["pathnames"])[:1000]

    if security_issue.get("source") == "cve":
        vulnerability_id = security_issue.get("reference")
        finding.unsaved_vulnerability_ids = [vulnerability_id]

    if locations_enabled() and (dep := get_dependency_from_component(component)):
        finding.unsaved_locations.append(dep)

    return finding


def get_severity(vulnerability):
    if vulnerability["severity"] <= 3.9:
        return "Low"
    if vulnerability["severity"] <= 6.9:
        return "Medium"
    if vulnerability["severity"] <= 8.9:
        return "High"
    return "Critical"
