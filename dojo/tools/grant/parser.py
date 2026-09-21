import json

from dojo.models import Finding


class GrantParser:

    """
    Parser for Grant JSON reports.

    Grant checks the licences in an SBOM or image against a licence policy. A package the
    policy denies — a forbidden licence, or one with no licence at all — is a compliance
    finding. Packages the policy allows are the compliant remainder and are not imported.
    """

    def get_scan_types(self):
        return ["Grant Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Grant license-compliance reports in JSON format, generated with 'grant check <target> -o json'."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for target in (data.get("run") or {}).get("targets", []):
            source = (target.get("source") or {}).get("ref")
            evaluation = target.get("evaluation") or {}
            for package in (evaluation.get("findings") or {}).get("packages", []):
                # Grant reports every evaluated package with its decision; only denied
                # packages are compliance findings.
                if str(package.get("decision")).lower() != "deny":
                    continue
                findings.append(self._to_finding(package, source, test))
        return findings

    def _to_finding(self, package, source, test):
        name = package.get("name")
        version = package.get("version")
        licenses = package.get("licenses") or []
        unlicensed = not licenses

        description = [f"**Package:** {name} {version}".strip()]
        if package.get("type"):
            description.append(f"**Type:** {package['type']}")
        if unlicensed:
            description.append("**License:** none declared — denied by policy")
        else:
            description.append(f"**License(s):** {', '.join(str(licence) for licence in licenses)}")
        if source:
            description.append(f"**Source:** {source}")
        description.extend(
            f"**Location:** {location['path']}"
            for location in package.get("locations") or []
            if isinstance(location, dict) and location.get("path")
        )

        return Finding(
            title=(
                f"{name} {version}: no license, denied by policy"
                if unlicensed
                else f"{name} {version}: license denied by policy"
            ).strip(),
            test=test,
            description="\n".join(description),
            # A policy denial is a compliance defect to act on.
            severity="High",
            component_name=name,
            component_version=version,
            vuln_id_from_tool=", ".join(str(licence) for licence in licenses) if licenses else "UNLICENSED",
            mitigation=(
                "Replace the dependency, obtain an exception for the licence, or add it to the "
                "Grant policy allow-list if the use is acceptable."
            ),
            static_finding=True,
            dynamic_finding=False,
        )
