import json
from contextlib import suppress

from dojo.models import Finding


class UptycsParser:

    """
    Parses an Uptycs vulnerabilities-query export.

    Mirrors pkg/tools/uptycs/connector/finding_converter field for field so a file import and an API
    sync deduplicate against each other instead of producing two copies of everything.

    Uptycs reports ONE ROW PER VULNERABLE PACKAGE, listing every CVE against it, so one row becomes
    one finding PER CVE - each is separately fixable and separately triaged. A row naming no CVE still
    becomes a single package finding, because a vulnerable package is worth recording even when Uptycs
    has not attached an identifier. See get_findings().
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName. Note it does NOT follow the
        # "<Vendor> - Connectors Import" pattern, so it cannot be derived - it has to be copied.
        return ["Uptycs Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Uptycs Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import an Uptycs vulnerabilities-query export (JSON). One row per vulnerable package "
            "becomes one finding per CVE. Matches the scan type used by the Uptycs connector so file "
            "and API findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Uptycs Parser.

        Mirrors the connector's Convert:
        - title: "<CVE> in <package>", or "Vulnerable package <package>" without one.
        - severity: derived from the row's CVSS score; Uptycs sends no severity word.
        - description: the package and version, the host, the OS, the asset group, and the row's other
          CVEs when it lists more than one.
        - component_name / component_version: the vulnerable package.
        - unique_id_from_tool: "uptycs-<asset id>-<package>[-<CVE>]".
        """
        return [
            "title",
            "severity",
            "description",
            "component_name",
            "component_version",
            "cvssv3_score",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "unsaved_vulnerability_ids",
            "tags",
            "active",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Uptycs Parser.

        Copied from the Uptycs block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. The component is the package, so the
        same CVE on two hosts hashes the same - the asset id in the identity is what keeps them apart.
        """
        return ["title", "severity", "component_name"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        findings = []
        for row in self.rows(data):
            cves = self.cves(row)
            if not cves:
                # A vulnerable package with no identifier is still worth recording.
                findings.append(self.build_finding(row, "", cves, test))
                continue
            findings.extend(self.build_finding(row, cve, cves, test) for cve in cves)
        return findings

    def rows(self, data):
        """
        Return the query rows in the export.

        Uptycs answers its query endpoint with {"items": [...]}, so that is the shape a saved export
        has. A bare array is accepted too.
        """
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
        if isinstance(data, dict):
            for key in ("items", "rows", "data", "results"):
                if isinstance(data.get(key), list):
                    return [row for row in data[key] if isinstance(row, dict)]

        msg = (
            "An Uptycs export is a vulnerabilities-query response, a JSON object with an 'items' "
            f"list; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def cves(self, row):
        """
        The row's CVE list, which Uptycs sends either as an array or as a COMMA-SEPARATED string.

        Its own decoder accepts both, so a string is split and trimmed - reading it whole would make
        one finding titled after every CVE at once.
        """
        value = row.get("cve_list")
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item or "").strip()]
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return []

    def build_finding(self, row, cve, cves, test):
        package = str(row.get("package_name") or "")

        finding = Finding(
            test=test,
            title=self.title(package, cve),
            severity=self.severity(row),
            description=self.describe(row, package, cves),
            component_name=package or None,
            component_version=str(row.get("package_version") or "") or None,
            unique_id_from_tool=self.unique_id(row, package, cve),
            # Uptycs reads an installed package inventory; nothing is exercised.
            static_finding=True,
            dynamic_finding=False,
            active=True,
        )
        finding.cvssv3_score = self.score(row)
        finding.unsaved_tags = self.tags(row)

        if cve:
            finding.unsaved_vulnerability_ids = [cve]
            finding.vuln_id_from_tool = cve
        return finding

    def unique_id(self, row, package, cve):
        base = f"uptycs-{row.get('upt_asset_id') or ''}-{package}"
        if cve:
            return f"{base}-{cve}"
        return base

    def title(self, package, cve):
        """The package name, or the literal word "package" when Uptycs did not name one."""
        name = package or "package"
        if cve:
            return f"{cve} in {name}"
        return f"Vulnerable package {name}"

    def severity(self, row):
        """
        Derived from the row's CVSS score - Uptycs sends no severity word to prefer.

        Every CVE fanned out of one row therefore shares the row's severity, because the row carries
        one score for the package rather than one per CVE.
        """
        score = self.score(row)
        if score >= 9:
            return "Critical"
        if score >= 7:
            return "High"
        if score >= 4:
            return "Medium"
        if score > 0:
            return "Low"
        return "Info"

    def score(self, row):
        """Uptycs' CVSS score, which may arrive quoted."""
        value = row.get("cvss_score")
        if isinstance(value, bool) or value is None:
            return 0.0
        if isinstance(value, int | float):
            return float(value)
        if isinstance(value, str):
            with suppress(ValueError):
                return float(value.strip() or 0)
        return 0.0

    def describe(self, row, package, cves):
        """
        The package, the host it is installed on, and the row's other CVEs.

        The CVE list is printed only when the row names MORE than one: with a single CVE the title
        already says it, and repeating it would add nothing.
        """
        lines = []

        def write(label, value):
            # The connector tests for emptiness WITHOUT trimming, which a plain truthiness test
            # reproduces exactly for strings.
            if value:
                lines.append(f"**{label}:** {value}")

        write("Package", f"{package} {row.get('package_version') or ''}".strip())
        write("Host", str(row.get("upt_hostname") or ""))
        write("OS", str(row.get("os") or ""))
        write("Asset group", str(row.get("upt_asset_group_name") or ""))

        if len(cves) > 1:
            write("CVEs", ", ".join(cves))
        return "\n".join(lines).strip()

    def tags(self, row):
        """The OS and the asset group, for filtering a fleet."""
        return [
            value
            for value in (
                str(row.get(key) or "").strip() for key in ("os", "upt_asset_group_name")
            )
            if value
        ]
