import json

from dojo.models import Finding


class SyftParser:

    """
    Parser for Syft JSON SBOMs.

    Syft catalogues the packages present in an image, directory or archive. It is an SBOM
    generator, not a vulnerability scanner: it reports what is installed, never whether it is
    vulnerable, and assigns no severity. Every catalogued package is imported as informational
    inventory.

    To find vulnerabilities in the same material, feed the SBOM to a scanner such as Grype or
    bomber, both of which DefectDojo also parses.
    """

    def get_scan_types(self):
        return ["Syft SBOM"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Syft SBOMs in Syft's native JSON format, generated with 'syft scan <target> -o syft-json'."

    def get_findings(self, file, test):
        data = json.load(file)
        source = (data.get("source") or {}).get("name")
        findings = []
        for artifact in data.get("artifacts", []):
            name = artifact.get("name")
            version = artifact.get("version")
            purl = artifact.get("purl")

            description = [f"**Package:** {name} {version}".strip()]
            if artifact.get("type"):
                description.append(f"**Type:** {artifact['type']}")
            if artifact.get("language"):
                description.append(f"**Language:** {artifact['language']}")
            if purl:
                description.append(f"**purl:** {purl}")
            licenses = self._licenses(artifact)
            description.append(f"**Licenses:** {', '.join(licenses) if licenses else 'none declared'}")
            description.extend(
                f"**Location:** {location['path']}"
                for location in artifact.get("locations") or []
                if location.get("path")
            )
            if source:
                description.append(f"**Source:** {source}")

            findings.append(Finding(
                title=f"{name}:{version}" if version else name,
                test=test,
                description="\n".join(description),
                # An SBOM entry records presence, not a defect.
                severity="Info",
                component_name=name,
                component_version=version,
                vuln_id_from_tool=purl or name,
                # Syft's artifact id is stable for a package in a given catalogue.
                unique_id_from_tool=artifact.get("id"),
                static_finding=True,
                dynamic_finding=False,
            ))
        return findings

    def _licenses(self, artifact):
        """Syft reports licences as objects; older schemas used bare strings."""
        values = []
        for licence in artifact.get("licenses") or []:
            if isinstance(licence, dict):
                value = licence.get("value") or licence.get("spdxExpression")
                if value:
                    values.append(value)
            elif licence:
                values.append(str(licence))
        return values
