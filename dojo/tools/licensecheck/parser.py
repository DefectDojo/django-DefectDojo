import json

from dojo.models import Finding


class LicensecheckParser:

    """
    Parser for licensecheck JSON reports.

    Unlike a plain licence inventory, licensecheck evaluates each dependency's licence for
    *compatibility* with the project's own licence. A package flagged incompatible is a
    genuine compliance finding; a compatible one is recorded as informational inventory.
    """

    def get_scan_types(self):
        return ["Licensecheck Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import licensecheck reports in JSON format, generated with 'licensecheck -f json'."

    def get_findings(self, file, test):
        data = json.load(file)
        project_license = data.get("project_license")
        findings = []
        for package in data.get("packages", []):
            name = package.get("name")
            version = package.get("version")
            licence = package.get("license")
            # licenseCompat is False when the dependency's licence conflicts with the
            # project's own licence.
            compatible = package.get("licenseCompat", True)

            description = [
                f"**Package:** {name} {version}".strip(),
                f"**License:** {licence or 'unknown'}",
                f"**Compatible with project license:** {compatible}",
            ]
            if project_license:
                description.append(f"**Project license:** {project_license}")
            if package.get("homePage"):
                description.append(f"**Homepage:** {package['homePage']}")

            findings.append(Finding(
                title=(
                    f"{name} {version}: license {licence} incompatible with project"
                    if not compatible
                    else f"{name} {version}: {licence}"
                ).strip(),
                test=test,
                description="\n".join(description),
                # An incompatible licence is the compliance finding; a compatible one is
                # inventory.
                severity="High" if not compatible else "Info",
                component_name=name,
                component_version=version,
                vuln_id_from_tool=licence or "UNKNOWN",
                mitigation=(
                    "Replace this dependency, or confirm the licence conflict is acceptable "
                    "for the project's distribution terms."
                    if not compatible
                    else None
                ),
                static_finding=True,
                dynamic_finding=False,
            ))
        return findings
