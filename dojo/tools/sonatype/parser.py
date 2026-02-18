import json

from django.conf import settings

from dojo.models import Finding
from dojo.tools.protocol import LocationData
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
        self.UNSAVED_LOCATIONS = []
        sonatype_report = json.load(json_output)
        findings = []
        if "components" in sonatype_report:
            components = sonatype_report["components"]

            # Collect product-level dependency locations for all components
            if settings.V3_FEATURE_LOCATIONS:
                for component in components:
                    if "componentIdentifier" in component:
                        comp_format = component["componentIdentifier"]["format"]
                        purl_type = SONATYPE_FORMAT_TO_PURL.get(comp_format)
                        if purl_type:
                            coords = component["componentIdentifier"]["coordinates"]
                            if comp_format == "maven":
                                purl_name = coords.get("artifactId", "")
                                purl_namespace = coords.get("groupId")
                                purl_version = coords.get("version", "")
                            elif comp_format in {"npm", "nuget"}:
                                purl_name = coords.get("packageId", "")
                                purl_namespace = None
                                purl_version = coords.get("version", "")
                            else:
                                purl_name = coords.get("name", "")
                                purl_namespace = None
                                purl_version = coords.get("version", "")
                            if purl_name:
                                dep_data = {"purl_type": purl_type, "name": purl_name, "version": purl_version}
                                if purl_namespace:
                                    dep_data["namespace"] = purl_namespace
                                self.UNSAVED_LOCATIONS.append(
                                    LocationData(type="dependency", data=dep_data),
                                )

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
        cvss_data = parse_cvss_data(security_issue["cvssVector"])
        if cvss_data:
            finding.cvssv3 = cvss_data.get("cvssv3")
            finding.cvssv3_score = cvss_data.get("cvssv3_score")

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
