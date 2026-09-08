import json
from contextlib import suppress
from datetime import datetime

from dojo.models import Finding

SEVERITY_BY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
# Automox also reports "none", "unknown" and "no_known_cves"; all are Info.
DEFAULT_SEVERITY = "Info"

# Automox timestamps, e.g. "2022-05-13T18:02:45+0000". %z reads every offset form the connector's
# two Go layouts accept - "+0000", "+02:00" and "Z" - and rejects a timestamp with no offset at all,
# which those layouts also reject. The second format is for a fractional-seconds variant.
DATE_FORMATS = ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z")


class AutomoxParser:

    """
    Parses an Automox awaiting-patch export.

    Mirrors pkg/tools/automox/connector/finding_converter field for field so a file import and an API
    sync deduplicate against each other instead of producing two copies of everything.

    Automox reports a missing patch per device, and the device's own details come from a SECOND
    endpoint - so an export carries both lists and the parser joins them on the package's server_id;
    see devices_by_id(). A package whose device is absent still becomes a finding, exactly as it does
    in the connector, where the device is a map lookup that can miss.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName. Note it does NOT follow the
        # "<Vendor> - Connectors Import" pattern, so it cannot be derived - it has to be copied.
        return ["Automox Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Automox Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import an Automox export of awaiting (missing) patches - the packages list, optionally "
            "with the devices list so each patch reports its device. Matches the scan type used by "
            "the Automox connector so file and API findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Automox Parser.

        Mirrors the connector's Convert:
        - title: "Missing patch: <display name>", falling back to the package name, then the id.
        - severity: Automox's own severity word; "none"/"unknown"/"no_known_cves" are all Info.
        - description: the package and version, repository, device, OS, CVEs and install status.
        - mitigation: install the available patch, naming the version when there is one.
        - component_name / component_version: the package name and version.
        - cvssv3_score: Automox's cve_score.
        - date: the package's create_time.
        - unique_id_from_tool: "automox-<package id>".
        """
        return [
            "title",
            "severity",
            "description",
            "mitigation",
            "component_name",
            "component_version",
            "cvssv3_score",
            "date",
            "unique_id_from_tool",
            "unsaved_vulnerability_ids",
            "tags",
            "active",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Automox Parser.

        Copied from the Automox block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. The component is the package, so the
        same missing patch on two devices hashes the same - the package id in the identity is what
        keeps them apart.
        """
        return ["title", "severity", "component_name"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        devices = self.devices_by_id(data)
        findings = []
        for row in self.packages(data):
            package_id = self.flex_int(row.get("id"))
            if package_id <= 0:
                # The id is the whole identity, and every row without one would collapse onto
                # "automox-0". Automox's own decoder rejects the whole page when an id is not
                # numeric; dropping the single row keeps the rest of the export importable.
                continue
            findings.append(self.build_finding(row, devices.get(self.flex_int(row.get("server_id"))), test))
        return findings

    def packages(self, data):
        """
        Return the awaiting-patch packages in the export.

        Automox answers /servers/<id>/packages with a bare array, so that is the shape a saved export
        has. An object naming its lists is accepted too, because the device details a finding needs
        come from a different endpoint and both have to travel in one file.
        """
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
        if isinstance(data, dict):
            for key in ("packages", "data", "results"):
                if isinstance(data.get(key), list):
                    return [row for row in data[key] if isinstance(row, dict)]

        msg = (
            "An Automox export is the awaiting-patch list - a JSON array of packages, or an object "
            f"with a 'packages' list; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def devices_by_id(self, data):
        """
        Index the devices in the export by id, so a package's server_id can name its device.

        Automox reports the device separately from the patch. When the export carries no devices the
        device-derived description lines are simply absent - the same result the connector produces
        when its own lookup misses.
        """
        if not isinstance(data, dict):
            return {}
        for key in ("devices", "servers"):
            rows = data.get(key)
            if isinstance(rows, list):
                return {
                    self.flex_int(row.get("id")): row
                    for row in rows
                    if isinstance(row, dict) and self.flex_int(row.get("id")) > 0
                }
        return {}

    def build_finding(self, row, device, test):
        version = str(row.get("version") or "")

        finding = Finding(
            test=test,
            title=self.title(row),
            severity=self.severity(row),
            description=self.describe(row, device),
            mitigation=self.mitigation(version),
            component_name=str(row.get("name") or "") or None,
            component_version=version or None,
            unique_id_from_tool=f"automox-{self.flex_int(row.get('id'))}",
            # Automox reads an installed package inventory; nothing is exercised.
            static_finding=True,
            dynamic_finding=False,
            active=True,
        )
        finding.cvssv3_score = self.score(row)
        finding.unsaved_tags = self.tags(row, device)

        if cves := self.cves(row):
            finding.unsaved_vulnerability_ids = cves
        if date := self.date(row):
            finding.date = date
        return finding

    def title(self, row):
        for key in ("display_name", "name"):
            if value := str(row.get(key) or ""):
                return f"Missing patch: {value}"
        return f"Missing patch: Automox package {self.flex_int(row.get('id'))}"

    def severity(self, row):
        label = str(row.get("severity") or "").strip().lower()
        return SEVERITY_BY_LABEL.get(label, DEFAULT_SEVERITY)

    def describe(self, row, device):
        """
        The package, where it came from, the device it is missing on, and its CVEs.

        The device lines are omitted when the export carries no matching device, which is what the
        connector does when its own device lookup misses.
        """
        lines = []

        def write(label, value):
            # The connector tests this value for emptiness WITHOUT trimming, so a value that is only
            # whitespace is written out - which a plain truthiness test reproduces exactly, since ""
            # is falsy and " " is not. Mirrored rather than tidied, so both paths render alike.
            if value:
                lines.append(f"**{label}:** {value}")

        write("Package", f"{row.get('display_name') or ''} {row.get('version') or ''}".strip())
        write("Repository", str(row.get("repo") or ""))

        if device is not None:
            write("Device", str(device.get("name") or ""))
            write("OS", f"{device.get('os_name') or ''} {device.get('os_version') or ''}".strip())

        if cves := self.cves(row):
            write("CVEs", ", ".join(cves))
        if not row.get("installed"):
            write("Status", "Patch available but not installed")
        return "\n".join(lines).strip()

    def mitigation(self, version):
        if version:
            return f"Install the available patch (version {version})."
        return "Install the available patch."

    def cves(self, row):
        """The package's CVE identifiers, in the order Automox lists them."""
        rows = row.get("cves")
        if not isinstance(rows, list):
            return []
        return [str(cve).strip() for cve in rows if str(cve or "").strip()]

    def tags(self, row, device):
        """
        The device's OS family and whether the patch needs a reboot.

        The connector's own comment says the severity is tagged too; its code does not tag it. The
        code is mirrored here rather than the comment - see the PR notes.
        """
        tags = []
        if device is not None and (family := str(device.get("os_family") or "")):
            tags.append(family)
        if row.get("requires_reboot"):
            tags.append("requires-reboot")
        return tags

    def date(self, row):
        value = str(row.get("create_time") or "").strip()
        if not value:
            return None
        for fmt in DATE_FORMATS:
            with suppress(ValueError):
                return datetime.strptime(value, fmt).date()
        return None

    def score(self, row):
        """
        Automox's cve_score, which may arrive quoted.

        A value that is not a number becomes 0.0 rather than an error: the connector's own decoder
        tolerates a non-numeric score, so an import must not fail on one.
        """
        with suppress(TypeError, ValueError):
            return float(str(row.get("cve_score") or 0).strip() or 0)
        return 0.0

    def flex_int(self, value):
        """Automox may send an id as a JSON number or a quoted string."""
        if isinstance(value, bool) or value is None:
            return 0
        if isinstance(value, int | float):
            return int(value)
        if isinstance(value, str):
            with suppress(ValueError):
                return int(float(value.strip() or 0))
        return 0
