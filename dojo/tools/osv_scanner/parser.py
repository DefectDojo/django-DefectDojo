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
        # Classifies severity levels (Classifie les niveaux de sévérité)
        return ("Medium" if severity_input == "MODERATE" else severity_input.lower().capitalize()) if severity_input != "" else "Low"

    def is_git_commit(self, version):
        # Check if the version is a Git commit (40 hex characters) (Vérifie si la version est un commit Git de 40 caractères hexadécimaux)
        return len(version) == 40 and all(c in "0123456789abcdef" for c in version)

    def compare_versions(self, v1, v2):
        # Compare two versions "X.Y.Z". Returns -1 if v1 < v2, 1 if v1 > v2, 0 if they are equal (Compare deux versions "X.Y.Z". Retourne -1 si v1 < v2, 1 si v1 > v2, 0 si égales)
        parts1 = [int(part) for part in v1.split(".") if part.isdigit()]
        parts2 = [int(part) for part in v2.split(".") if part.isdigit()]

        for p1, p2 in zip(parts1, parts2):
            if p1 > p2:
                return 1
            elif p1 < p2:
                return -1

        return 0 if len(parts1) == len(parts2) else (1 if len(parts1) > len(parts2) else -1)

    def get_closest_fixed_version(self, package_version, ranges):
        """
        Find the closest fixed version based on the installed version.
        Handles GIT, ECOSYSTEM, and SEMVER types. (Trouve la version corrigée la plus proche en fonction de la version installée. Gère les types GIT, ECOSYSTEM et SEMVER.)
        """
        fixed_versions = []
        fixed_commits = []
        introduced_versions = []

        is_git_version = self.is_git_commit(package_version)
        is_semver = "." in package_version and not is_git_version

        for range_item in ranges:
            range_type = range_item.get("type")
            repo_url = range_item.get("repo", "")

            for event in range_item.get("events", []):
                if "introduced" in event and event["introduced"] != "0":
                    introduced_versions.append(event["introduced"])

                if "fixed" in event:
                    fixed_value = event["fixed"]

                    if range_type == "GIT":
                        if repo_url:
                            fixed_commits.append(f"{repo_url}/commit/{fixed_value}")
                        else:
                            fixed_commits.append(fixed_value)

                    elif range_type in ["ECOSYSTEM", "SEMVER"]:
                        fixed_versions.append(fixed_value)

        closest_introduced = None
        introduced_versions.sort(key=lambda v: [int(p) for p in v.split(".") if p.isdigit()])

        for introduced_version in introduced_versions:
            if self.compare_versions(introduced_version, package_version) <= 0:
                closest_introduced = introduced_version

        if is_git_version:
            return ", ".join(fixed_commits) if fixed_commits else None, closest_introduced

        closest_fix = None
        fixed_versions.sort(key=lambda v: [int(p) for p in v.split(".") if p.isdigit()])

        for fixed_version in fixed_versions:
            if self.compare_versions(fixed_version, package_version) > 0:
                closest_fix = fixed_version
                break

        return closest_fix if closest_fix else (
            ", ".join(fixed_versions) if fixed_versions else None), closest_introduced

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
                    mitigation = None
                    introduced_versions = []

                    # Make sure we have an affected section to work with
                    if (affected := vulnerability.get("affected")) is not None:
                        if len(affected) > 0:
                            # Pull the package purl if present
                            if (vulnerabilitypackage := affected[0].get("package", "")) != "":
                                vulnerabilitypackagepurl = vulnerabilitypackage.get("purl", "")
                            # Extract the CWE
                            if (cwe := affected[0].get("database_specific", {}).get("cwes", None)) is not None:
                                cwe = cwe[0]["cweId"]

                            # Get mitigation and introduced versions (Obtenez la mitigation et les versions introduites)
                            mitigation, introduced_versions = self.get_closest_fixed_version(package_version, affected[0].get("ranges", []))

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

                    if introduced_versions:
                        description += f"**Introduces a vulnerability**: {', '.join(introduced_versions)}\n"

                    related_cves = vulnerability.get("related", [])
                    if related_cves:
                        description += f"**Related CVEs**: {', '.join(related_cves)}\n"

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

                    if vulnerabilityid:
                        finding.unsaved_vulnerability_ids = [vulnerabilityid]

                    findings.append(finding)

        return findings
