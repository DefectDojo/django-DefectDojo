import json

from dojo.models import Finding

# npm advisory severities, which pnpm reuses verbatim.
SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "moderate": "Medium",
    "low": "Low",
    "info": "Info",
}
DEFAULT_SEVERITY = "Medium"


class PnpmAuditParser:

    """Parses the JSON report of `pnpm audit --json`."""

    def get_scan_types(self):
        return ["pnpm Audit Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "pnpm Audit Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import the JSON report of `pnpm audit --json`. pnpm emits the npm v6 'advisories' "
            "envelope, not the npm 7+ 'vulnerabilities' one."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the pnpm Audit Parser.

        Fields:
        - title: Advisory title, prefixed with the affected module.
        - severity: Mapped from the advisory severity (critical/high/moderate/low/info).
        - description: Advisory title, vulnerable and patched ranges, and the dependency path.
        - mitigation: The patched version range reported by the advisory.
        - component_name: module_name from the advisory.
        - component_version: version from the advisory's findings entry.
        - cwe: Parsed from the advisory's "CWE-nnn" string when present.
        - vuln_id_from_tool: github_advisory_id, falling back to the numeric advisory id.
        - references: Advisory URL.
        - static_finding: True - pnpm audit reads the lock file.

        NOTE: GHSA identifiers are reported through unsaved_vulnerability_ids. pnpm's report carries
        no CVE field, so a CVE is not available from this tool.
        """
        return [
            "title",
            "severity",
            "description",
            "mitigation",
            "component_name",
            "component_version",
            "cwe",
            "vuln_id_from_tool",
            "references",
            "static_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the pnpm Audit Parser.

        Fields:
        - component_name: module_name from the advisory.
        - component_version: the installed version the advisory matched.
        - vuln_id_from_tool: the GHSA id, which is stable per advisory.
        """
        return ["component_name", "component_version", "vuln_id_from_tool"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        if not isinstance(data, dict):
            msg = (
                "A pnpm audit report is a JSON object with an 'advisories' key; "
                f"got {type(data).__name__}."
            )
            raise TypeError(msg)

        findings = {}
        for advisory in (data.get("advisories") or {}).values():
            if not isinstance(advisory, dict):
                continue
            module = advisory.get("module_name") or ""
            identifier = advisory.get("github_advisory_id") or str(advisory.get("id") or "")
            # One advisory can match several installed versions of the same module, and each is a
            # separately fixable finding.
            for version in self.affected_versions(advisory):
                key = (module, version, identifier)
                if key not in findings:
                    findings[key] = self.build_finding(advisory, module, version, test)
        return list(findings.values())

    def affected_versions(self, advisory):
        """Every distinct installed version this advisory matched; ("",) when none is reported."""
        versions = []
        for entry in advisory.get("findings") or []:
            if isinstance(entry, dict) and (version := entry.get("version")) and version not in versions:
                versions.append(version)
        return versions or [""]

    def build_finding(self, advisory, module, version, test):
        title = advisory.get("title") or "Unnamed advisory"
        severity = SEVERITY_MAP.get((advisory.get("severity") or "").lower(), DEFAULT_SEVERITY)
        patched = advisory.get("patched_versions") or ""

        finding = Finding(
            test=test,
            title=f"{module}: {title}" if module else title,
            severity=severity,
            description=self.build_description(advisory, module, version),
            mitigation=(
                f"Upgrade {module} to {patched}." if patched
                else f"Upgrade {module} to a version that is not affected."
            ),
            component_name=module or None,
            component_version=version or None,
            cwe=self.parse_cwe(advisory.get("cwe")),
            vuln_id_from_tool=advisory.get("github_advisory_id") or str(advisory.get("id") or "") or None,
            references=advisory.get("url") or None,
            # pnpm audit reads the lock file; it does not exercise the application.
            static_finding=True,
            dynamic_finding=False,
        )
        if ghsa := advisory.get("github_advisory_id"):
            # The report has no CVE field, so the GHSA id is the only public identifier available.
            finding.unsaved_vulnerability_ids = [ghsa]
        return finding

    def parse_cwe(self, raw):
        """The advisory reports a CWE as the string "CWE-918"; DefectDojo wants the number."""
        if isinstance(raw, str) and raw.upper().startswith("CWE-"):
            number = raw[4:].strip()
            if number.isdigit():
                return int(number)
        return None

    def build_description(self, advisory, module, version):
        parts = [advisory.get("title") or "Unnamed advisory"]
        if module:
            parts.append(f"**Module:** {module}")
        if version:
            parts.append(f"**Installed version:** {version}")
        if vulnerable := advisory.get("vulnerable_versions"):
            parts.append(f"**Vulnerable versions:** {vulnerable}")
        if patched := advisory.get("patched_versions"):
            parts.append(f"**Patched versions:** {patched}")
        if paths := self.dependency_paths(advisory):
            # pnpm reports how the package was pulled in, which is what tells a reader whether they
            # can act on it directly or have to go through a parent dependency.
            parts.append(f"**Dependency paths:** {', '.join(paths)}")
        return "\n".join(parts)

    def dependency_paths(self, advisory):
        paths = []
        for entry in advisory.get("findings") or []:
            if not isinstance(entry, dict):
                continue
            for path in entry.get("paths") or []:
                if path not in paths:
                    paths.append(path)
        return paths
