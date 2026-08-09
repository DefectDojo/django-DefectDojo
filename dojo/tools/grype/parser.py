import json

from dojo.models import Finding


class GrypeParser:

    """
    Parser for Grype JSON reports.

    Grype scans an SBOM, image or directory for known vulnerabilities in its packages. Each
    match pairs a vulnerability with the package it affects; Grype's own severity is used, and
    the CVE, CWE, CVSS score and fixed version are carried across where present.
    """

    SEVERITY = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "negligible": "Info",
        "unknown": "Info",
    }

    def get_scan_types(self):
        return ["Grype Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Grype reports in JSON format, generated with 'grype <target> -o json'."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for match in data.get("matches", []):
            vulnerability = match.get("vulnerability") or {}
            artifact = match.get("artifact") or {}
            findings.append(self._to_finding(match, vulnerability, artifact, test))
        return findings

    def _to_finding(self, match, vulnerability, artifact, test):
        vuln_id = vulnerability.get("id")
        name = artifact.get("name")
        version = artifact.get("version")
        fix = vulnerability.get("fix") or {}
        fixed_versions = fix.get("versions") or []
        related = [rv.get("id") for rv in match.get("relatedVulnerabilities", []) if rv.get("id")]

        description = []
        if vulnerability.get("description"):
            description.append(vulnerability["description"])
        description.extend([
            f"**Vulnerability:** {vuln_id}",
            f"**Package:** {name} {version}".strip(),
        ])
        if artifact.get("type"):
            description.append(f"**Package type:** {artifact['type']}")
        if vulnerability.get("dataSource"):
            description.append(f"**Data source:** {vulnerability['dataSource']}")
        if fix.get("state"):
            description.append(f"**Fix state:** {fix['state']}")
        if related:
            description.append(f"**Related:** {', '.join(related)}")

        finding = Finding(
            title=f"{vuln_id} in {name} {version}".strip(),
            test=test,
            description="\n".join(description),
            severity=self.SEVERITY.get(str(vulnerability.get("severity")).lower(), "Info"),
            component_name=name,
            component_version=version,
            vuln_id_from_tool=vuln_id,
            file_path=self._location(artifact),
            mitigation=(
                f"Upgrade {name} to {' or '.join(fixed_versions)}."
                if fixed_versions and name
                else None
            ),
            static_finding=True,
            dynamic_finding=False,
        )

        # Grype reports the primary vulnerability plus any it is aliased to; the CVE ids
        # among them are the vulnerability ids.
        cves = [v for v in [vuln_id, *related] if str(v).upper().startswith("CVE-")]
        if cves:
            finding.unsaved_vulnerability_ids = cves

        cwes = self._cwe(vulnerability.get("cwes"))
        if cwes is not None:
            finding.cwe = cwes

        score = self._cvss_score(vulnerability.get("cvss"))
        if score is not None:
            finding.cvssv3_score = score
        return finding

    def _location(self, artifact):
        for location in artifact.get("locations") or []:
            if location.get("path"):
                return location["path"]
        return None

    def _cwe(self, cwes):
        # Grype reports CWEs either as bare 'CWE-522' strings or as objects carrying a
        # 'cwe' field; a Finding holds a single integer.
        for cwe in cwes or []:
            value = cwe.get("cwe") if isinstance(cwe, dict) else cwe
            digits = "".join(ch for ch in str(value) if ch.isdigit())
            if digits:
                return int(digits)
        return None

    def _cvss_score(self, cvss):
        """Grype lists one CVSS block per source; take the highest base score."""
        scores = [
            entry.get("metrics", {}).get("baseScore")
            for entry in cvss or []
            if isinstance(entry, dict) and entry.get("metrics", {}).get("baseScore") is not None
        ]
        return max(scores) if scores else None
