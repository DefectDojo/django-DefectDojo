import json

from dojo.models import Finding

# Mirrors toSeverity() in the Lacework connector's converter; anything unrecognised becomes Info.
SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
DEFAULT_SEVERITY = "Info"

# Lacework marks a fixed or otherwise resolved vulnerability in the row itself, and the connector's
# applyStatus() keeps those out of the active set rather than dropping them.
INACTIVE_STATUSES = {"fixed", "resolved"}


class LaceworkParser:

    """
    Parses a Lacework (FortiCNAPP) vulnerability export.

    Lacework reports two different things, and the connector's converter treats them differently:
    container/image vulnerabilities are STATIC findings keyed by image, host vulnerabilities are
    DYNAMIC findings keyed by hostname. Both mappings are mirrored from
    pkg/tools/lacework/converter so a file import and an API sync deduplicate against each other.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanType().
        return ["Lacework - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Lacework - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Lacework (FortiCNAPP) container or host vulnerability export (JSON). Matches "
            "the scan type used by the Lacework connector so file and API findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Lacework Parser.

        Mirrors the connector's converter:
        - title: "<CVE> - <package> (<version>)", falling back as the converter's title() does.
        - severity: critical/high/medium/low, anything else Info.
        - description: CVE, severity, image or host context, package, namespace, installed version.
        - component_name / component_version: the feature key's name and version.
        - mitigation: set only when the row reports a fix available AND a fixed version.
        - references: the CVE link, host rows only.
        - unique_id_from_tool: "<image or host>|<CVE>|<package>|<version>".
        - static_finding / dynamic_finding: container rows are static, host rows are dynamic.
        - active: false for a row Lacework reports as fixed or resolved.
        """
        return [
            "title",
            "severity",
            "description",
            "component_name",
            "component_version",
            "mitigation",
            "references",
            "unique_id_from_tool",
            "tags",
            "static_finding",
            "dynamic_finding",
            "active",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Lacework Parser.

        Copied from the Lacework block in dojo-pro pro_settings.py, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. Diverging would stop file findings
        merging with API-synced ones.
        """
        return ["title", "severity", "component_name"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        rows = self.extract_rows(data)

        findings = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            finding = (
                self.build_host_finding(row, test) if self.is_host_row(row)
                else self.build_container_finding(row, test)
            )
            key = finding.unique_id_from_tool
            if key not in findings:
                findings[key] = finding
        return list(findings.values())

    def extract_rows(self, data):
        """Lacework's query API wraps rows under "data"; a saved export is often the bare array."""
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("data", "rows"):
                if isinstance(data.get(key), list):
                    return data[key]
        msg = (
            "A Lacework export is a JSON array of vulnerability rows, or an object with a 'data' "
            f"list; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def is_host_row(self, row):
        """
        Decide which of the connector's two mappings applies.

        A host row carries the installed version under featureKey.version_installed and identifies
        the machine by hostname or mid; a container row carries featureKey.version and an imageId.
        """
        feature = row.get("featureKey") or {}
        if "version_installed" in feature:
            return True
        return "mid" in row or "imageId" not in row

    def build_container_finding(self, row, test):
        feature = row.get("featureKey") or {}
        image_info = ((row.get("evalCtx") or {}).get("image_info")) or {}
        package = feature.get("name") or ""
        version = feature.get("version") or ""
        vuln_id = row.get("vulnId") or ""
        image = image_info.get("repo") or row.get("imageId") or ""

        finding = Finding(
            test=test,
            title=self.title(vuln_id, package, version),
            severity=self.severity(row),
            description=self.fields([
                ("CVE", vuln_id),
                ("Severity", row.get("severity")),
                ("Image", image),
                ("Registry", image_info.get("registry")),
                ("Image Digest", image_info.get("digest")),
                ("Package", package),
                ("Namespace", feature.get("namespace")),
                ("Installed Version", version),
            ]),
            component_name=package or None,
            component_version=version or None,
            # An image scan reads a built artifact, so the converter marks it static.
            static_finding=True,
            dynamic_finding=False,
            unique_id_from_tool="|".join([row.get("imageId") or "", vuln_id, package, version]),
        )
        finding.unsaved_tags = [
            f"image:{image}", f"registry:{image_info.get('registry') or ''}", "source:container",
        ]
        self.apply_status(finding, row.get("status"))
        # The converter only offers a fix when Lacework reports both a fix flag and a version.
        fix = row.get("fixInfo") or {}
        if fix.get("fix_available") == 1 and fix.get("fixed_version"):
            finding.mitigation = f"Upgrade {package} to {fix['fixed_version']}."
        if vuln_id:
            finding.unsaved_vulnerability_ids = [vuln_id]
        return finding

    def build_host_finding(self, row, test):
        feature = row.get("featureKey") or {}
        cve_props = row.get("cveProps") or {}
        package = feature.get("name") or ""
        version = feature.get("version_installed") or ""
        vuln_id = row.get("vulnId") or ""
        host = ((row.get("evalCtx") or {}).get("hostname")) or ""
        if not host:
            # The converter falls back to the machine id when the hostname is missing.
            host = f"mid-{row.get('mid')}"

        finding = Finding(
            test=test,
            title=self.title(vuln_id, package, version),
            severity=self.severity(row),
            description=self.fields([
                ("CVE", vuln_id),
                ("Severity", row.get("severity")),
                ("Host", (row.get("evalCtx") or {}).get("hostname")),
                ("Package", package),
                ("Namespace", feature.get("namespace")),
                ("Installed Version", version),
                ("Description", cve_props.get("description")),
            ]),
            component_name=package or None,
            component_version=version or None,
            references=cve_props.get("link") or None,
            # A host scan looks at a running machine, so the converter marks it dynamic.
            static_finding=False,
            dynamic_finding=True,
            unique_id_from_tool=f"{host}|{vuln_id}|{package}|{version}",
        )
        finding.unsaved_tags = [f"host:{host}", "source:host"]
        self.apply_status(finding, row.get("status"))
        # Host rows report fix_available as a STRING, unlike the container rows' integer.
        fix = row.get("fixInfo") or {}
        available = str(fix.get("fix_available") or "")
        if available not in {"", "0"} and fix.get("fixed_version"):
            finding.mitigation = f"Upgrade {package} to {fix['fixed_version']}."
        if vuln_id:
            finding.unsaved_vulnerability_ids = [vuln_id]
        return finding

    def title(self, vuln_id, package, version):
        """Build the title as the converter does: identifier, then package, then version."""
        identifier = vuln_id or "Vulnerability"
        if package and version:
            return f"{identifier} - {package} ({version})"
        if package:
            return f"{identifier} - {package}"
        return identifier

    def severity(self, row):
        return SEVERITY_MAP.get((row.get("severity") or "").strip().lower(), DEFAULT_SEVERITY)

    def apply_status(self, finding, status):
        """Converter applyStatus(): a fixed or resolved row is imported, but not as active."""
        if (status or "").strip().lower() in INACTIVE_STATUSES:
            finding.active = False
            finding.is_mitigated = True
        else:
            finding.active = True

    def fields(self, pairs):
        """Converter writeField(): "**Label:** value" lines, skipping the empty ones."""
        return "\n".join(f"**{label}:** {value}" for label, value in pairs if value)
