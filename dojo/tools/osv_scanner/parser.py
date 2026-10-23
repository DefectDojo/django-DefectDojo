import json
import math

from cvss.exceptions import CVSSError

from dojo.location.feature import locations_enabled
from dojo.models import Finding
from dojo.tools.locations import LocationData
from dojo.utils import parse_cvss_data

OSV_ECOSYSTEM_TO_PURL = {
    "npm": "npm", "pypi": "pypi", "go": "golang", "maven": "maven",
    "crates.io": "cargo", "rubygems": "gem", "nuget": "nuget",
    "packagist": "composer", "hex": "hex", "pub": "pub",
    "cocoapods": "cocoapods", "swifturl": "swift",
    "alpine": "apk", "debian": "deb",
}
CVSS_SEVERITY_TYPES = {"CVSS_V2", "CVSS_V3", "CVSS_V4"}
CVSS_FIELDS = (
    "cvssv2", "cvssv2_score", "cvssv3", "cvssv3_score", "cvssv4", "cvssv4_score",
)


class OSVScannerParser:

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the OSV Parser.

        Fields:
        - title: Created from vulnerability id and package name.
        - description: Custom description made from: vulnerability, source_type, & package_ecosystem.
        - severity: Set to severity from OSV Scanner that has been translated into Defect Dojo format.
        - static_finding: Set to true.
        - dynamic_finding: Set to false.
        - component_name: Set to package name from OSV Scanner.
        - component_version: Set to package version from OSV Scanner.
        - cwe: Set to cwe outputted from OSV Scanner.
        - file_path: Set to source path from OSV Scanner.
        """
        return [
            "title",
            "description",
            "severity",
            "static_finding",
            "dynamic_finding",
            "component_name",
            "component_version",
            "cwe",
            "file_path",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the OSV Parser.

        Fields:
        - title: Created from vulnerability id and package name.
        - description: Custom description made from: vulnerability, source_type, & package_ecosystem.
        - severity: Set to severity from OSV Scanner that has been translated into Defect Dojo format.
        """
        return [
            "title",
            "description",
            "severity",
        ]

    def get_scan_types(self):
        return ["OSV Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "OSV Scan"

    def get_description_for_scan_types(self, scan_type):
        return "OSV scan output can be imported in JSON format (option --format json)."

    def classify_severity(self, severity_input):
        return ("Medium" if severity_input == "MODERATE" else severity_input.lower().capitalize()) if severity_input else "Low"

    def _parse_cvss_data(self, vulnerability):
        cvss_data_by_version = {}
        for severity_entry in vulnerability.get("severity") or []:
            if not isinstance(severity_entry, dict) or severity_entry.get("type") not in CVSS_SEVERITY_TYPES:
                continue
            vector = severity_entry.get("score")
            if not isinstance(vector, str) or not vector:
                continue
            try:
                cvss_data = parse_cvss_data(vector)
            except CVSSError:
                continue
            if version := cvss_data.get("major_version"):
                cvss_data_by_version[version] = cvss_data
        return cvss_data_by_version

    def _get_group_severity(self, package, vulnerability):
        aliases = vulnerability.get("aliases") or []
        if not isinstance(aliases, list):
            aliases = []
        vulnerability_ids = {
            identifier for identifier in [vulnerability.get("id"), *aliases]
            if isinstance(identifier, str) and identifier
        }
        for group in package.get("groups") or []:
            if not isinstance(group, dict):
                continue
            group_ids = set()
            for field in ("ids", "aliases"):
                identifiers = group.get(field)
                if isinstance(identifiers, list):
                    group_ids.update(identifier for identifier in identifiers if isinstance(identifier, str))
            if not vulnerability_ids.intersection(group_ids):
                continue
            try:
                score = float(group.get("max_severity"))
            except (TypeError, ValueError):
                continue
            if not math.isfinite(score):
                continue
            if score <= 0:
                return "Info"
            if score < 4:
                return "Low"
            if score < 7:
                return "Medium"
            if score < 9:
                return "High"
            return "Critical"
        return None

    def get_findings(self, file, test):
        try:
            data = json.load(file)
        except json.decoder.JSONDecodeError:
            return []
        findings = []
        for result in data.get("results", []):
            # Extract source locations if present
            source_path = result.get("source", {}).get("path", "")
            source_type = result.get("source", {}).get("type", "")
            for package in result.get("packages", []):
                package_name = package.get("package", {}).get("name")
                package_version = package.get("package", {}).get("version")
                package_ecosystem = package.get("package", {}).get("ecosystem", "")
                for vulnerability in package.get("vulnerabilities", []):
                    vulnerabilityid = vulnerability.get("id", "")
                    vulnerabilitysummary = vulnerability.get("summary", "")
                    vulnerabilitydetails = vulnerability.get("details", "")
                    vulnerabilitypackagepurl = ""
                    cwe = None
                    unsaved_cwes = []
                    mitigations_by_type = {}  # Dictionary to store corrected versions by type

                    # Make sure we have an affected section to work with
                    if (affected := vulnerability.get("affected")) is not None:
                        if len(affected) > 0:
                            # Pull the package purl if present
                            if (vulnerabilitypackage := affected[0].get("package", "")):
                                vulnerabilitypackagepurl = vulnerabilitypackage.get("purl", "")
                            # Extract the CWE
                            if (cwe := affected[0].get("database_specific", {}).get("cwes", None)) is not None:
                                unsaved_cwes = [entry["cweId"] for entry in cwe if entry.get("cweId")]
                                cwe = cwe[0]["cweId"]
                            # Extraction of corrected versions by type
                            ranges = affected[0].get("ranges", [])
                            for range_item in ranges:
                                range_type = range_item.get("type", "")
                                repo_url = range_item.get("repo", "")
                                for event in range_item.get("events", []):
                                    if "fixed" in event:
                                        fixed_value = event["fixed"]
                                        # GIT URL format if applicable
                                        if range_type == "GIT" and repo_url:
                                            formatted_value = f"{repo_url}/commit/{fixed_value}"
                                        else:
                                            formatted_value = fixed_value
                                        # Add to the list by type
                                        if range_type not in mitigations_by_type:
                                            mitigations_by_type[range_type] = []
                                        mitigations_by_type[range_type].append(formatted_value)

                    # Creation of formatted mitigation text
                    mitigation_text = None
                    if mitigations_by_type:
                        mitigation_text = "**Upgrade to versions**:\n"
                        for typ, versions in mitigations_by_type.items():
                            mitigation_text += f"\t{typ} :\n"
                            for version in versions:
                                mitigation_text += f"\t\t- {version}\n"
                    # Create some references
                    reference = ""
                    for ref in vulnerability.get("references", []):
                        reference += ref.get("url") + "\n"
                    # Define the description
                    description = vulnerabilitysummary + "\n"
                    description += f"**Source type**: {source_type}\n"
                    description += f"**Package ecosystem**: {package_ecosystem}\n"
                    description += f"**Vulnerability details**: {vulnerabilitydetails}\n"
                    description += f"**Vulnerability package purl**: {vulnerabilitypackagepurl}\n"
                    cvss_data_by_version = self._parse_cvss_data(vulnerability)
                    cvss_data = {
                        field: version_data[field]
                        for version_data in cvss_data_by_version.values()
                        for field in CVSS_FIELDS
                        if version_data.get(field) is not None
                    }
                    cvss_severity = next(
                        (
                            cvss_data_by_version[version]["severity"]
                            for version in (4, 3, 2)
                            if cvss_data_by_version.get(version, {}).get("severity")
                        ),
                        None,
                    )
                    if cvss_severity == "None":
                        cvss_severity = "Info"
                    database_specific = vulnerability.get("database_specific") or {}
                    group_severity = self._get_group_severity(package, vulnerability)
                    sev = database_specific.get("severity") or group_severity or cvss_severity
                    finding = Finding(
                        title=f"{vulnerabilityid}_{package_name}",
                        test=test,
                        description=description,
                        severity=self.classify_severity(sev),
                        **cvss_data,
                        static_finding=True,
                        dynamic_finding=False,
                        component_name=package_name,
                        component_version=package_version,
                        cwe=cwe,
                        file_path=source_path,
                        references=reference,
                    )

                    if mitigation_text:
                        finding.mitigation = mitigation_text

                    # The OSV id first, then its aliases: a GHSA-keyed advisory names its CVE only there
                    aliases = vulnerability.get("aliases") or []
                    if not isinstance(aliases, list):
                        aliases = []
                    vulnerability_ids = [vulnerabilityid, *aliases]
                    vulnerability_ids = list(dict.fromkeys(x.strip() for x in vulnerability_ids if isinstance(x, str) and x.strip()))
                    if vulnerability_ids:
                        finding.unsaved_vulnerability_ids = vulnerability_ids
                    if unsaved_cwes:
                        finding.unsaved_cwes = unsaved_cwes
                    if locations_enabled() and (dep := self.get_dependency_info(package_ecosystem, package_name, package_version)):
                        finding.unsaved_locations.append(dep)
                    findings.append(finding)
                if locations_enabled() and (dep := self.get_dependency_info(package_ecosystem, package_name, package_version)):
                    test.unsaved_metadata.append(dep)
        return findings

    def get_dependency_info(self, pacakge_ecosystem, package_name, package_version):
        if purl_type := OSV_ECOSYSTEM_TO_PURL.get(pacakge_ecosystem.lower()):
            purl_string = f"pkg:/{purl_type}/{package_name}/{package_version}"
            return LocationData.dependency(purl=purl_string)
        return None
