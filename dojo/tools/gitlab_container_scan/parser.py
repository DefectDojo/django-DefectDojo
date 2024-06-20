import json
import textwrap

from dateutil.parser import parse

from dojo.models import Finding


class GitlabContainerScanParser:
    """
    GitLab's container scanning report
    See more: https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/blob/master/dist/container-scanning-report-format.json
    """

    def get_scan_types(self):
        return ["GitLab Container Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "GitLab Container Scan Scan"

    def get_description_for_scan_types(self, scan_type):
        return "GitLab Container Scan report file can be imported in JSON format (option --json)."

    def _get_dependency_version(self, dependency):
        return dependency.get("version", "")

    def _get_dependency_name(self, dependency):
        if "package" in dependency and "name" in dependency["package"]:
            return dependency["package"]["name"]
        return ""

    def _get_identifier_cve(self, identifier):
        return (
            identifier["value"]
            if identifier.get("type", "no-type") == "cve"
            else None
        )

    def _get_identifier_cwe(self, identifier):
        return (
            identifier["value"]
            if identifier.get("type", "no-type") == "cwe"
            else None
        )

    def _get_first_cve(self, identifiers):
        cwe = ""
        # Find the first match of a cve
        for identifier in identifiers:
            cve = self._get_identifier_cve(identifier)
            # query the cwe as a backup
            cwe = self._get_identifier_cwe(identifier)
            if cve:
                return cve
        # Looks like a cve was not found, try to use the cwe, otherwise "fail"
        return f"CWE-{cwe}" if cwe else None

    def _get_package_string(self, dependency):
        dependency_name = self._get_dependency_name(dependency)
        dependency_version = self._get_dependency_version(dependency)
        if dependency_name:
            if dependency_version:
                return f"{dependency_name}-{dependency_version}"
            return dependency_name
        # check if name is missing, but at least version is here
        return (
            f"unknown-package-{dependency_version}"
            if dependency_version
            else None
        )

    def get_findings(self, file, test):
        findings = []
        data = json.load(file)
        # parse date
        date = None
        if "scan" in data and "end_time" in data["scan"]:
            date = parse(data["scan"]["end_time"])

        # Vulnerabilities is stored on vulnerabilities key
        vulnerabilities = data["vulnerabilities"]
        for vulnerability in vulnerabilities:
            title = vulnerability.get("message")
            dependency = vulnerability["location"]["dependency"]
            identifiers = vulnerability["identifiers"]
            # In new versiona, the message field is no longer in report, so
            # build the title from other parts
            if not title:
                issue_string = self._get_first_cve(identifiers)
                location_string = self._get_package_string(dependency)
                title = f"{issue_string} in {location_string}"
            description = vulnerability["description"]
            severity = self.normalise_severity(vulnerability["severity"])
            finding = Finding(
                title=title,
                date=date,
                test=test,
                description=description,
                severity=severity,
                static_finding=True,
                dynamic_finding=False,
                unique_id_from_tool=vulnerability["id"],
            )

            # Add component fields if not empty
            unsaved_vulnerability_ids = []
            for identifier in identifiers:
                cve = self._get_identifier_cve(identifier)
                if cve:
                    unsaved_vulnerability_ids.append(cve)
                cwe = self._get_identifier_cwe(identifier)
                if cwe:
                    finding.cwe = cwe
            if unsaved_vulnerability_ids:
                finding.unsaved_vulnerability_ids = unsaved_vulnerability_ids

            # Check package key before name as both is optional on GitLab
            # schema
            dependency_name = self._get_dependency_name(dependency)
            if dependency_name:
                finding.component_name = textwrap.shorten(
                    dependency_name, width=190, placeholder="...",
                )

            dependency_version = self._get_dependency_version(dependency)
            if dependency_version:
                finding.component_version = textwrap.shorten(
                    dependency_version, width=90, placeholder="...",
                )

            if "solution" in vulnerability:
                finding.mitigation = vulnerability["solution"]

            findings.append(finding)

        return findings

    def normalise_severity(self, severity):
        """
        Normalise GitLab's severity to DefectDojo's
        (Critical, High, Medium, Low, Unknown, Info) -> (Critical, High, Medium, Low, Info)
        """
        return "Info" if severity == "Unknown" else severity
