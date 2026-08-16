"""Parser for the CSV export of the Seal Security CLI (https://www.seal.security)"""

import csv
import io
import re

from dojo.models import Finding

VULNERABILITY_SEPARATOR = "|"
EMBEDDED_PACKAGE_SEPARATOR = "&"

# A vulnerability reached through an embedded (shaded) package is reported as
# "CVE-2021-1234(via shaded lib1&lib2)" rather than as a bare identifier.
EMBEDDED_VIA_PATTERN = re.compile(r"^(?P<vulnerability_id>.+?)\(via shaded (?P<packages>.+)\)$")

DESCRIPTION_TEMPLATE = """**Package:** {package}
**Ecosystem:** {ecosystem}
**Vulnerability:** {vulnerability_id}
"""

EMBEDDED_VIA_TEMPLATE = """
The vulnerability is not in {package} itself. It reaches the project through the \
following package(s) embedded (shaded) into it: {packages}.
"""

SEALED_MITIGATION_TEMPLATE = """Update {package} to the sealed version {sealed_version}. \
Sealed versions backport the security fix without changing the major version, so they \
are drop-in replacements.
"""

NO_FIX_MITIGATION = "Seal has no sealed version for this package version yet."


def convert_severity(score):
    """
    Map a Seal unified score onto a DefectDojo severity.

    The score column is absent from the CSV written by current CLI versions, in which
    case no severity can be derived from the report and Medium is used.
    """
    if not score:
        return "Medium"
    try:
        score = float(score)
    except ValueError:
        return "Medium"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Info"


def split_vulnerabilities(vulnerabilities):
    """Split a Vulnerabilities cell into (vulnerability_id, embedding packages) pairs."""
    results = []
    for raw_entry in vulnerabilities.split(VULNERABILITY_SEPARATOR):
        entry = raw_entry.strip()
        if not entry:
            continue
        match = EMBEDDED_VIA_PATTERN.match(entry)
        if match:
            packages = [
                package.strip()
                for package in match.group("packages").split(EMBEDDED_PACKAGE_SEPARATOR)
                if package.strip()
            ]
            results.append((match.group("vulnerability_id").strip(), packages))
        else:
            results.append((entry, []))
    return results


class SealParser:
    def get_scan_types(self):
        return ["Seal Security Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Seal Security Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import the CSV export of the Seal Security CLI, produced by `seal scan --csv <file>`."

    def get_findings(self, file, test):
        content = file.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8-sig")
        # A byte order mark survives when the report is handed over already decoded, and
        # would otherwise end up glued to the first column name
        content = content.lstrip("\ufeff")
        # A scan that finds nothing leaves the file empty rather than writing a header.
        if not content.strip():
            return []

        findings = []
        for row in csv.DictReader(io.StringIO(content)):
            findings.extend(self.get_findings_for_package(row, test))
        return findings

    def get_findings_for_package(self, row, test):
        package_name = (row.get("Library") or "").strip()
        package_version = (row.get("Version") or "").strip()
        ecosystem = (row.get("Ecosystem") or "").strip()
        sealed_version = (row.get("Sealed Version") or "").strip()
        can_seal = (row.get("Can Seal") or "").strip().upper() == "TRUE"
        severity = convert_severity((row.get("Score") or "").strip())

        if not package_name:
            return []

        package = f"{package_name} {package_version}".strip()
        has_fix = can_seal and bool(sealed_version)
        if has_fix:
            mitigation = SEALED_MITIGATION_TEMPLATE.format(
                package=package_name, sealed_version=sealed_version,
            )
        else:
            mitigation = NO_FIX_MITIGATION

        findings = []
        for vulnerability_id, embedded_via in split_vulnerabilities(row.get("Vulnerabilities") or ""):
            description = DESCRIPTION_TEMPLATE.format(
                package=package,
                ecosystem=ecosystem,
                vulnerability_id=vulnerability_id,
            )
            if embedded_via:
                description += EMBEDDED_VIA_TEMPLATE.format(
                    package=package_name,
                    packages=", ".join(embedded_via),
                )

            finding = Finding(
                test=test,
                title=f"{package} - {vulnerability_id}",
                severity=severity,
                description=description,
                mitigation=mitigation,
                component_name=package_name,
                component_version=package_version,
                vuln_id_from_tool=vulnerability_id,
                fix_available=has_fix,
                static_finding=True,
                dynamic_finding=False,
            )
            finding.unsaved_vulnerability_ids = [vulnerability_id]
            findings.append(finding)

        return findings
