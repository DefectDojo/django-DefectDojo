import json

from dojo.models import Finding

# Severities as the Elixir Security Advisories data records them, lowercase.
SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "moderate": "Medium",
    "medium": "Medium",
    "low": "Low",
}
# Not every advisory in the Elixir data carries a severity, and one without is still a real
# published vulnerability, so it is imported at the neutral level rather than dropped.
DEFAULT_SEVERITY = "Medium"


class MixAuditParser:

    """Parses the JSON report of `mix deps.audit --format json`."""

    def get_scan_types(self):
        return ["Mix Audit Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Mix Audit Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import the JSON report of `mix deps.audit --format json` (Elixir/Hex)."

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Mix Audit Parser.

        Fields:
        - title: Advisory title, prefixed with the affected Hex package.
        - severity: Mapped from the advisory severity (critical/high/moderate/low).
        - description: Advisory description, the installed version and the vulnerable ranges.
        - mitigation: The first patched versions the advisory lists.
        - component_name: Hex package name.
        - component_version: The version pinned in mix.lock.
        - vuln_id_from_tool: Advisory id, which is a GHSA id.
        - references: Advisory URL.
        - publish_date: disclosure_date from the advisory.
        - static_finding: True - mix deps.audit reads mix.lock.

        NOTE: GHSA identifiers are reported through unsaved_vulnerability_ids. The Elixir advisory
        data has no CVE field, so a CVE is not available from this tool.
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
            "publish_date",
            "static_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Mix Audit Parser.

        Fields:
        - component_name: Hex package name.
        - component_version: The version pinned in mix.lock.
        - vuln_id_from_tool: The advisory id, stable per advisory.
        """
        return ["component_name", "component_version", "vuln_id_from_tool"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        if not isinstance(data, dict):
            msg = (
                "A mix deps.audit report is a JSON object with a 'vulnerabilities' key; "
                f"got {type(data).__name__}. Note that the FIRST run of `mix deps.audit` in a clean "
                "checkout prints compiler output before the JSON; capture a second run."
            )
            raise TypeError(msg)

        findings = {}
        for entry in data.get("vulnerabilities") or []:
            if not isinstance(entry, dict):
                continue
            dependency = entry.get("dependency") or {}
            advisory = entry.get("advisory") or {}
            package = dependency.get("package") or advisory.get("package") or ""
            version = dependency.get("version") or ""
            advisory_id = advisory.get("id") or ""
            key = (package, version, advisory_id)
            if key not in findings:
                findings[key] = self.build_finding(advisory, package, version, test)
        return list(findings.values())

    def build_finding(self, advisory, package, version, test):
        title = advisory.get("title") or "Unnamed advisory"
        severity = SEVERITY_MAP.get((advisory.get("severity") or "").lower(), DEFAULT_SEVERITY)
        patched = advisory.get("first_patched_versions") or []

        finding = Finding(
            test=test,
            title=f"{package}: {title}" if package else title,
            severity=severity,
            description=self.build_description(advisory, package, version),
            mitigation=self.build_mitigation(package, patched),
            component_name=package or None,
            component_version=version or None,
            vuln_id_from_tool=advisory_id if (advisory_id := advisory.get("id")) else None,
            references=advisory.get("url") or None,
            publish_date=advisory.get("disclosure_date") or None,
            # mix deps.audit reads mix.lock; it does not exercise the application.
            static_finding=True,
            dynamic_finding=False,
        )
        if advisory_id:
            # The Elixir advisory ids are GHSA ids, and there is no CVE field to fall back on.
            finding.unsaved_vulnerability_ids = [advisory_id]
        return finding

    def build_description(self, advisory, package, version):
        parts = [advisory.get("description") or advisory.get("title") or "Unnamed advisory"]
        if package:
            parts.append(f"**Package:** {package}")
        if version:
            parts.append(f"**Installed version:** {version}")
        if ranges := advisory.get("vulnerable_version_ranges"):
            parts.append(f"**Vulnerable ranges:** {', '.join(str(item) for item in ranges)}")
        if patched := advisory.get("first_patched_versions"):
            parts.append(f"**First patched versions:** {', '.join(str(item) for item in patched)}")
        return "\n".join(parts)

    def build_mitigation(self, package, patched):
        if patched:
            return f"Upgrade {package} to {', '.join(str(item) for item in patched)} or later."
        return f"Upgrade {package} to a version that is not affected by this advisory."
