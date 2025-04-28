import json

from dojo.models import Finding


class OSVScannerParser:

    def get_scan_types(self):
        return ["OSV Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "OSV Scan"

    def get_description_for_scan_types(self, scan_type):
        return "OSV scan output can be imported in JSON format (option --format json)."

    def classify_severity(self, severity_input):
        return ("Medium" if severity_input == "MODERATE" else severity_input.lower().capitalize()) if severity_input != "" else "Low"

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
                    mitigations_by_type = {}  # Dictionary to store corrected versions by type

                    # Make sure we have an affected section to work with
                    if (affected := vulnerability.get("affected")) is not None:
                        if len(affected) > 0:
                            # Pull the package purl if present
                            if (vulnerabilitypackage := affected[0].get("package", "")) != "":
                                vulnerabilitypackagepurl = vulnerabilitypackage.get("purl", "")
                            # Extract the CWE
                            if (cwe := affected[0].get("database_specific", {}).get("cwes", None)) is not None:
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
                    sev = vulnerability.get("database_specific", {}).get("severity", "")
                    finding = Finding(
                        title=f"{vulnerabilityid}_{package_name}",
                        test=test,
                        description=description,
                        severity=self.classify_severity(sev),
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

                    if vulnerabilityid:
                        finding.unsaved_vulnerability_ids = [vulnerabilityid]
                    findings.append(finding)
        return findings
