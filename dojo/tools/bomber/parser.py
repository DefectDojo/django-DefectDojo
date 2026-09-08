import json

from dojo.models import Finding


class BomberParser:

    """
    Parser for bomber JSON reports.

    bomber reads an existing SBOM and looks each component up against a vulnerability
    provider (OSV, OSS Index, Snyk or GitLab). Findings are grouped under the package
    coordinates, which bomber reports as a purl.
    """

    # bomber normalises every provider onto its own scale, which uses MODERATE rather
    # than the more common MEDIUM.
    SEVERITY = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MODERATE": "Medium",
        "LOW": "Low",
        "UNSPECIFIED": "Info",
    }

    def get_scan_types(self):
        return ["bomber Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import bomber reports in JSON format, generated with 'bomber scan --output json <sbom>'."

    def get_findings(self, file, test):
        data = json.load(file)
        provider = data.get("meta", {}).get("provider")
        findings = []
        for package in data.get("packages", []):
            coordinates = package.get("coordinates")
            name, version = self._split_purl(coordinates)
            findings.extend(
                self._to_finding(vulnerability, coordinates, name, version, provider, test)
                for vulnerability in package.get("vulnerabilities", [])
            )
        return findings

    def _to_finding(self, vulnerability, coordinates, name, version, provider, test):
        identifier = vulnerability.get("id")
        cve = vulnerability.get("cve")

        description = []
        if vulnerability.get("description"):
            description.append(vulnerability["description"])
        if coordinates:
            description.append(f"**Package:** {coordinates}")
        if provider:
            description.append(f"**Provider:** {provider}")

        finding = Finding(
            title=vulnerability.get("title") or identifier,
            test=test,
            description="\n".join(description),
            severity=self.SEVERITY.get(str(vulnerability.get("severity")).upper(), "Medium"),
            component_name=name,
            component_version=version,
            vuln_id_from_tool=identifier,
            static_finding=True,
            dynamic_finding=False,
        )
        # bomber repeats the identifier in the cve field when the advisory has one; some
        # providers return an advisory id such as GHSA-xxxx there instead.
        if cve and cve.upper().startswith("CVE-"):
            finding.unsaved_vulnerability_ids = [cve]
        elif identifier and identifier.upper().startswith("CVE-"):
            finding.unsaved_vulnerability_ids = [identifier]
        return finding

    def _split_purl(self, coordinates):
        """Pull the component name and version out of a purl such as pkg:maven/group/name@1.2.3."""
        if not coordinates:
            return None, None
        without_scheme = coordinates.split("pkg:", 1)[-1]
        name, _, version = without_scheme.partition("@")
        # Drop the purl type prefix (maven/, npm/, golang/ ...), keeping any namespace.
        _, _, name = name.partition("/")
        return name or None, version or None
