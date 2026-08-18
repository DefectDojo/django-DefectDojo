import json

from dojo.models import Finding


class UvAuditParser:

    """
    Parser for 'uv audit' JSON reports.

    uv audits a locked dependency set against the Python advisory databases. Like pip-audit,
    it reports advisories without a severity, so every finding is imported as Medium.

    The JSON schema is marked ``preview`` by uv itself and may change without warning; the
    schema version is recorded on each Finding so a report from a newer uv is identifiable.
    """

    def get_scan_types(self):
        return ["uv audit Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import 'uv audit' reports in JSON format, generated with 'uv audit --output-format json'."

    def get_findings(self, file, test):
        data = json.load(file)
        schema_version = (data.get("schema") or {}).get("version")
        findings = []
        for vulnerability in data.get("vulnerabilities", []):
            dependency = vulnerability.get("dependency") or {}
            name = dependency.get("name")
            version = dependency.get("version")
            advisory_id = vulnerability.get("display_id") or vulnerability.get("id")
            aliases = vulnerability.get("aliases") or []
            fix_versions = vulnerability.get("fix_versions") or []

            description = []
            if vulnerability.get("summary"):
                description.append(vulnerability["summary"])
            if vulnerability.get("description"):
                description.append(vulnerability["description"])
            description.append(f"**Advisory:** {advisory_id}")
            if name:
                description.append(f"**Package:** {name} {version}".strip())
            if aliases:
                description.append(f"**Aliases:** {', '.join(aliases)}")
            if vulnerability.get("published"):
                description.append(f"**Published:** {vulnerability['published']}")
            if schema_version:
                description.append(f"**uv audit schema version:** {schema_version}")

            finding = Finding(
                title=f"{name}: {advisory_id}" if name else advisory_id,
                test=test,
                description="\n".join(description),
                # uv audit reports advisories without a severity, as pip-audit does.
                severity="Medium",
                component_name=name,
                component_version=version,
                vuln_id_from_tool=advisory_id,
                references=vulnerability.get("link") or None,
                mitigation=(
                    f"Upgrade {name} to {' or '.join(fix_versions)}."
                    if fix_versions and name
                    else None
                ),
                static_finding=True,
                dynamic_finding=False,
            )
            # uv reports the advisory under its own id and lists CVE and GHSA aliases
            # alongside it; only the CVEs are vulnerability ids.
            cves = [alias for alias in aliases if alias.upper().startswith("CVE-")]
            if advisory_id and advisory_id.upper().startswith("CVE-"):
                cves.insert(0, advisory_id)
            if cves:
                finding.unsaved_vulnerability_ids = cves
            findings.append(finding)
        return findings
