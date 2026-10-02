import json

from dojo.models import Finding

# Packagist advisory severities, lowercase in the report.
SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "moderate": "Medium",
    "low": "Low",
}
# An advisory with no severity recorded still describes a real published vulnerability, so it is
# imported rather than dropped; Medium is the neutral choice DefectDojo uses elsewhere.
DEFAULT_SEVERITY = "Medium"


class ComposerAuditParser:

    """Parses the JSON report of `composer audit --format=json`."""

    def get_scan_types(self):
        return ["Composer Audit Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Composer Audit Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import the JSON report of `composer audit --format=json --locked` (PHP/Packagist)."

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Composer Audit Parser.

        Fields:
        - title: Advisory title, prefixed with the affected package and its version.
        - severity: Mapped from the advisory severity (critical/high/medium/low).
        - description: Advisory title, affected version range and report date.
        - mitigation: Tells the reader to move off the affected range.
        - component_name: packageName from the advisory.
        - vuln_id_from_tool: advisoryId (the Packagist PKSA id).
        - references: link from the advisory.
        - static_finding: True - composer audit reads the lock file, it does not run the application.

        NOTE: CVE and GHSA identifiers are reported through unsaved_vulnerability_ids.
        """
        return [
            "title",
            "severity",
            "description",
            "mitigation",
            "component_name",
            "vuln_id_from_tool",
            "references",
            "static_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Composer Audit Parser.

        Fields:
        - component_name: packageName from the advisory.
        - vuln_id_from_tool: advisoryId, which is stable per advisory.

        NOTE: component_version is deliberately absent. composer audit reports the affected
        version RANGE, never the version actually installed, so there is nothing to dedupe on.
        """
        return ["component_name", "vuln_id_from_tool"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        if not isinstance(data, dict):
            msg = (
                "A composer audit report is a JSON object with an 'advisories' key; "
                f"got {type(data).__name__}."
            )
            raise TypeError(msg)

        findings = {}
        # "advisories" maps a package name to the list of advisories affecting it, so one package
        # with several advisories yields several findings.
        for package, advisories in (data.get("advisories") or {}).items():
            for advisory in advisories or []:
                if not isinstance(advisory, dict):
                    continue
                advisory_id = advisory.get("advisoryId") or ""
                key = (package, advisory_id)
                if key not in findings:
                    findings[key] = self.build_finding(advisory, package, test)
        return list(findings.values())

    def build_finding(self, advisory, package, test):
        title = advisory.get("title") or "Unnamed advisory"
        severity = SEVERITY_MAP.get((advisory.get("severity") or "").lower(), DEFAULT_SEVERITY)

        finding = Finding(
            test=test,
            title=f"{package}: {title}" if package else title,
            severity=severity,
            description=self.build_description(advisory, package),
            mitigation=self.build_mitigation(package, advisory.get("affectedVersions")),
            # component_version is not set: the advisory names an affected RANGE, not the
            # installed version, which lives in composer.lock rather than the report.
            component_name=package or None,
            vuln_id_from_tool=advisory.get("advisoryId") or None,
            references=advisory.get("link") or None,
            # composer audit reads the lock file; it does not exercise the application.
            static_finding=True,
            dynamic_finding=False,
        )
        if identifiers := self.vulnerability_ids(advisory):
            finding.unsaved_vulnerability_ids = identifiers
        return finding

    def vulnerability_ids(self, advisory):
        """
        Collect the advisory's public identifiers.

        The CVE is a top-level field but is often null, in which case the GitHub advisory id from
        "sources" is the only public identifier the report carries.
        """
        identifiers = []
        if cve := advisory.get("cve"):
            identifiers.append(cve)
        for source in advisory.get("sources") or []:
            if not isinstance(source, dict):
                continue
            remote_id = source.get("remoteId") or ""
            if remote_id.startswith("GHSA-") and remote_id not in identifiers:
                identifiers.append(remote_id)
        return identifiers

    def build_description(self, advisory, package):
        parts = [advisory.get("title") or "Unnamed advisory"]
        if package:
            parts.append(f"**Package:** {package}")
        if affected := advisory.get("affectedVersions"):
            parts.append(f"**Affected versions:** {affected}")
        if reported := advisory.get("reportedAt"):
            parts.append(f"**Reported:** {reported}")
        return "\n".join(parts)

    def build_mitigation(self, package, affected):
        if affected:
            # composer audit states the affected RANGE rather than a single fixed version, so the
            # advice has to be phrased around leaving that range.
            return f"Upgrade {package} to a version outside the affected range {affected}."
        return f"Upgrade {package} to a version that is not affected by this advisory."
