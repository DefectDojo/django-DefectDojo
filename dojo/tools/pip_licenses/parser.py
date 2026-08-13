import json

from dojo.models import Finding


class PipLicensesParser:

    """
    Parser for pip-licenses JSON reports.

    pip-licenses inventories the licence of every installed Python distribution. It is a
    compliance inventory rather than a vulnerability scanner: it reports what is installed and
    under which licence, and judges nothing. Packages whose licence it could not determine are
    raised above informational, because an undetermined licence is itself a compliance gap.
    """

    # Values pip-licenses uses when a distribution declares no usable licence metadata.
    UNKNOWN_LICENSES = {"unknown", "unknown license", "", "none"}

    def get_scan_types(self):
        return ["pip-licenses Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import pip-licenses reports in JSON format, generated with 'pip-licenses --format=json'."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for package in data or []:
            name = package.get("Name")
            version = package.get("Version")
            licence = package.get("License")
            undetermined = str(licence).strip().lower() in self.UNKNOWN_LICENSES

            description = [
                f"**Package:** {name} {version}".strip(),
                f"**License:** {licence or 'not declared'}",
            ]
            if package.get("Author"):
                description.append(f"**Author:** {package['Author']}")
            if package.get("URL"):
                description.append(f"**URL:** {package['URL']}")
            if undetermined:
                description.append(
                    "pip-licenses could not determine a licence for this distribution. "
                    "Confirm the licence before redistributing.",
                )

            findings.append(Finding(
                title=f"{name} {version}: {licence or 'no license declared'}".strip(),
                test=test,
                description="\n".join(description),
                # An inventory entry is informational; an undetermined licence is a gap.
                severity="Low" if undetermined else "Info",
                component_name=name,
                component_version=version,
                vuln_id_from_tool=str(licence) if licence else "UNKNOWN",
                static_finding=True,
                dynamic_finding=False,
            ))
        return findings
