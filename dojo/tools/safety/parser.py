import json

from dojo.models import Finding


class SafetyParser:

    """
    Parser for Safety JSON reports.

    Safety checks installed Python packages against the PyUp advisory database. Advisories
    carry a CVE and a severity only where PyUp has assigned one; many PVE advisories have
    neither, so severity falls back to Medium and the docs page says so.
    """

    SEVERITY = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }

    def get_scan_types(self):
        return ["Safety Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Safety reports in JSON format, generated with 'safety check --json'."

    def get_findings(self, file, test):
        data = json.load(file)
        meta = data.get("report_meta") or {}
        findings = []
        for vulnerability in data.get("vulnerabilities", []):
            # Safety keeps ignored advisories in the report, flagged rather than removed.
            if vulnerability.get("ignored"):
                continue
            findings.append(self._to_finding(vulnerability, meta, test))
        return findings

    def _to_finding(self, vulnerability, meta, test):
        advisory_id = vulnerability.get("vulnerability_id")
        package = vulnerability.get("package_name")
        version = vulnerability.get("analyzed_version")
        cve = vulnerability.get("CVE")
        fixed = [v for v in (vulnerability.get("fixed_versions") or []) if v]

        description = []
        if vulnerability.get("advisory"):
            description.append(vulnerability["advisory"])
        description.extend([
            f"**Advisory:** {advisory_id}",
            f"**Package:** {package} {version}".strip(),
        ])
        if vulnerability.get("vulnerable_spec"):
            description.append(f"**Vulnerable spec:** {', '.join(vulnerability['vulnerable_spec'])}")
        if vulnerability.get("is_transitive"):
            description.append("**Transitive dependency:** yes")
        if vulnerability.get("published_date"):
            description.append(f"**Published:** {vulnerability['published_date']}")
        if meta.get("safety_version"):
            description.append(f"**Safety version:** {meta['safety_version']}")

        references = vulnerability.get("more_info_url")
        resources = vulnerability.get("resources") or []
        if resources:
            references = "\n".join([references, *resources]) if references else "\n".join(resources)

        finding = Finding(
            title=f"{package}: {advisory_id}" if package else advisory_id,
            test=test,
            description="\n".join(description),
            severity=self.SEVERITY.get(str(vulnerability.get("severity")).lower(), "Medium"),
            component_name=package,
            component_version=version,
            vuln_id_from_tool=advisory_id,
            references=references or None,
            mitigation=(
                f"Upgrade {package} to {' or '.join(fixed)}."
                if fixed and package
                else None
            ),
            static_finding=True,
            dynamic_finding=False,
        )
        if cve:
            finding.unsaved_vulnerability_ids = [cve]
        return finding
