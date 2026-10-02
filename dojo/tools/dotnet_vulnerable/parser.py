import json
import re

from dojo.models import Finding

# `dotnet list package --vulnerable` reports the NuGet advisory severity already capitalised.
SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "moderate": "Medium",
    "medium": "Medium",
    "low": "Low",
}
DEFAULT_SEVERITY = "Medium"

# The report carries no advisory identifier of its own, only a URL. For a GitHub advisory URL the
# GHSA id is the last path segment, and that is the only public identifier available.
GHSA_IN_URL = re.compile(r"(GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})", re.IGNORECASE)


class DotnetVulnerableParser:

    """Parses the JSON report of `dotnet list package --vulnerable --format json`."""

    def get_scan_types(self):
        return ["Dotnet Vulnerable Packages Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Dotnet Vulnerable Packages Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import the JSON report of "
            "`dotnet list package --vulnerable --include-transitive --format json` (NuGet)."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Dotnet Vulnerable Packages Parser.

        Fields:
        - title: Package, resolved version and the advisory severity.
        - severity: Mapped from the NuGet advisory severity (Critical/High/Moderate/Low).
        - description: Package, versions, whether it is a direct or transitive dependency, project
          and target framework.
        - mitigation: Differs for a transitive package, which cannot be upgraded directly.
        - component_name: Package id.
        - component_version: resolvedVersion, which is what is actually in the build.
        - vuln_id_from_tool: The GHSA id taken from the advisory URL.
        - references: advisoryurl.
        - static_finding: True - the command reads the restored dependency graph.

        NOTE: GHSA identifiers are reported through unsaved_vulnerability_ids. The report has no CVE
        field, so a CVE is not available from this tool.
        """
        return [
            "title",
            "severity",
            "description",
            "mitigation",
            "component_name",
            "component_version",
            "vuln_id_from_tool",
            "references",
            "static_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Dotnet Vulnerable Packages Parser.

        Fields:
        - component_name: Package id.
        - component_version: resolvedVersion.
        - vuln_id_from_tool: The GHSA id from the advisory URL.
        """
        return ["component_name", "component_version", "vuln_id_from_tool"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        if not isinstance(data, dict):
            msg = (
                "A `dotnet list package` report is a JSON object with a 'projects' key; "
                f"got {type(data).__name__}."
            )
            raise TypeError(msg)

        findings = {}
        for project in data.get("projects") or []:
            if not isinstance(project, dict):
                continue
            project_path = project.get("path") or ""
            # A clean project has no "frameworks" key at all rather than an empty list.
            for framework in project.get("frameworks") or []:
                if not isinstance(framework, dict):
                    continue
                target = framework.get("framework") or ""
                # Both lists have to be walked: a vulnerable package is very often pulled in by
                # something else rather than referenced directly, and only the transitive list
                # names it. Transitive entries carry no requestedVersion.
                for key, direct in (("topLevelPackages", True), ("transitivePackages", False)):
                    for package in framework.get(key) or []:
                        if not isinstance(package, dict):
                            continue
                        self.collect(package, direct, project_path, target, findings, test)
        return list(findings.values())

    def collect(self, package, direct, project_path, target, findings, test):
        name = package.get("id") or ""
        resolved = package.get("resolvedVersion") or ""
        for vulnerability in package.get("vulnerabilities") or []:
            if not isinstance(vulnerability, dict):
                continue
            url = vulnerability.get("advisoryurl") or ""
            identifier = self.advisory_id(url)
            # The same package can appear under several target frameworks of the same project; that
            # is one finding, not one per framework.
            key = (name, resolved, identifier or url)
            if key not in findings:
                findings[key] = self.build_finding(
                    package, vulnerability, direct, project_path, target, identifier, test,
                )

    def advisory_id(self, url):
        if match := GHSA_IN_URL.search(url or ""):
            return match.group(1)
        return ""

    def build_finding(self, package, vulnerability, direct, project_path, target, identifier, test):
        name = package.get("id") or ""
        resolved = package.get("resolvedVersion") or ""
        severity = SEVERITY_MAP.get(
            (vulnerability.get("severity") or "").lower(), DEFAULT_SEVERITY,
        )

        finding = Finding(
            test=test,
            title=f"{name} {resolved} has a known {severity.lower()}-severity vulnerability",
            severity=severity,
            description=self.build_description(package, direct, project_path, target),
            mitigation=self.build_mitigation(name, direct),
            component_name=name or None,
            component_version=resolved or None,
            vuln_id_from_tool=identifier or None,
            references=vulnerability.get("advisoryurl") or None,
            # The command reads the restored dependency graph; it does not run the application.
            static_finding=True,
            dynamic_finding=False,
        )
        if identifier:
            finding.unsaved_vulnerability_ids = [identifier]
        return finding

    def build_description(self, package, direct, project_path, target):
        parts = [f"**Package:** {package.get('id') or ''}"]
        if resolved := package.get("resolvedVersion"):
            parts.append(f"**Resolved version:** {resolved}")
        if requested := package.get("requestedVersion"):
            # Only a directly referenced package reports the version that was asked for.
            parts.append(f"**Requested version:** {requested}")
        parts.append(f"**Dependency:** {'direct' if direct else 'transitive'}")
        if project_path:
            parts.append(f"**Project:** {project_path}")
        if target:
            parts.append(f"**Target framework:** {target}")
        return "\n".join(parts)

    def build_mitigation(self, name, direct):
        if direct:
            return f"Upgrade the {name} package reference to a version without this advisory."
        # A transitive package is not in the project file, so telling someone to "upgrade it" is
        # not actionable on its own.
        return (
            f"{name} is a transitive dependency. Upgrade whichever direct dependency pulls it in, "
            f"or add an explicit {name} reference pinned to a fixed version."
        )
