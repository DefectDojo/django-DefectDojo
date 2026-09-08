import json
from contextlib import suppress

from dojo.models import Finding


class NozomiParser:

    """
    Parses a Nozomi Vantage node_cves export.

    Mirrors pkg/tools/nozomi/connector/finding_converter field for field so a file import and an API
    sync deduplicate against each other instead of producing two copies of everything.

    It also mirrors the connector's QUERY, not only its converter: the connector asks Vantage for
    "node_cves | where resolved != true", so a resolved record is something an API sync can never
    produce. A hand-run query can return them, and importing one would create an active finding for
    something Nozomi has already closed - so they are skipped here too. See get_findings().

    A node_cves record is denormalised: every row carries its own asset context, so nothing has to be
    joined.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName. Note it does NOT follow the
        # "<Vendor> - Connectors Import" pattern, so it cannot be derived - it has to be copied.
        return ["Nozomi Vantage Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Nozomi Vantage Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Nozomi Vantage node_cves export (JSON) - per-asset OT/ICS vulnerabilities with "
            "their asset context. Resolved records are skipped, matching the connector's query. "
            "Matches the scan type used by the Nozomi connector so file and API findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Nozomi Parser.

        Mirrors the connector's Convert:
        - title: "<CVE> on <asset>", then the CVE alone.
        - severity: derived from the CVE's CVSS base score; Nozomi sends no severity word.
        - description: the asset's label, type, vendor, product, firmware, OS and zone, the weakness
          name, then the CVE summary.
        - mitigation: apply the latest hotfix, or at least the minimum one.
        - component_name / component_version: the asset's product and firmware version.
        - references: every CVE reference, one per line.
        - cwe: parsed from "CWE-###".
        - unique_id_from_tool: "nozomi-<record id>", or "nozomi-<CVE>-<asset id>" without one.
        """
        return [
            "title",
            "severity",
            "description",
            "mitigation",
            "component_name",
            "component_version",
            "cvssv3_score",
            "references",
            "cwe",
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
        Return the list of fields used for deduplication in the Nozomi Parser.

        Copied from the Nozomi block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. The component is the OT product, so
        the same CVE on two different devices stays two findings.
        """
        return ["title", "severity", "component_name"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        findings = []
        for row in self.rows(data):
            if row.get("resolved") is True:
                # The connector's query is "where resolved != true", so an API sync can never produce
                # this record. Importing it would open a finding Nozomi has already closed.
                continue
            findings.append(self.build_finding(row, test))
        return findings

    def rows(self, data):
        """
        Return the node_cves records in the export.

        Vantage's query endpoint answers {"result": [...]}, so that is the shape a saved export has.
        A bare array is accepted too.
        """
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
        if isinstance(data, dict):
            for key in ("result", "results", "data"):
                if isinstance(data.get(key), list):
                    return [row for row in data[key] if isinstance(row, dict)]

        msg = (
            "A Nozomi export is a node_cves query response, a JSON object with a 'result' list; got "
            f"{type(data).__name__}."
        )
        raise TypeError(msg)

    def build_finding(self, row, test):
        cve = str(row.get("cve") or "")

        finding = Finding(
            test=test,
            title=self.title(row, cve),
            severity=self.severity(row),
            description=self.describe(row),
            mitigation=self.mitigation(row),
            component_name=str(row.get("node_product_name") or "") or None,
            component_version=str(row.get("node_firmware_version") or "") or None,
            references=self.references(row),
            cwe=self.cwe(row),
            unique_id_from_tool=self.unique_id(row, cve),
            # Vantage matches a passively-built asset inventory against advisories; nothing is
            # exercised, which matters in OT where active probing is not acceptable.
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

    def unique_id(self, row, cve):
        """Vantage's own record id, falling back to the CVE and the asset it was found on."""
        if record_id := str(row.get("id") or ""):
            return f"nozomi-{record_id}"
        return f"nozomi-{cve}-{row.get('asset_id') or ''}"

    def title(self, row, cve):
        """
        "<CVE> on <asset>", then the CVE alone.

        Note there is no asset-only form: a record with no CVE has nothing to name it by, so it falls
        through to the generic title rather than being titled after the device.
        """
        label = str(row.get("node_label") or "")
        if cve and label:
            return f"{cve} on {label}"
        if cve:
            return cve
        return "Nozomi vulnerability"

    def severity(self, row):
        """
        Derived from the CVE's CVSS base score - Nozomi sends no severity word to prefer.

        An unscored record is Info rather than being dropped: in an OT estate the asset context is
        worth recording even when the score is missing.
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
        """Vantage's CVSS base score, which may arrive quoted."""
        value = row.get("cve_score")
        if isinstance(value, bool) or value is None:
            return 0.0
        if isinstance(value, int | float):
            return float(value)
        if isinstance(value, str):
            with suppress(ValueError):
                return float(value.strip() or 0)
        return 0.0

    def describe(self, row):
        """
        The asset context first, then the CVE summary, separated by a blank line.

        A node_cves record is denormalised, so all of this travels on the row - which is what makes an
        OT finding readable without a second lookup.
        """
        fields = (
            ("Asset", "node_label"),
            ("Type", "node_type"),
            ("Vendor", "node_vendor"),
            ("Product", "node_product_name"),
            ("Firmware", "node_firmware_version"),
            ("OS", "node_os"),
            ("Zone", "zone"),
            ("Weakness", "cwe_name"),
        )
        lines = []
        for label, key in fields:
            # The connector tests for emptiness WITHOUT trimming, which a plain truthiness test
            # reproduces exactly for strings.
            if value := str(row.get(key) or ""):
                lines.append(f"**{label}:** {value}")

        text = "\n".join(lines)
        if summary := str(row.get("cve_summary") or ""):
            if text:
                text += "\n\n"
            text += summary
        return text.strip()

    def mitigation(self, row):
        """The latest hotfix, then the minimum one - the floor a device has to reach."""
        if hotfix := str(row.get("latest_hotfix") or ""):
            return f"Apply hotfix {hotfix}."
        if minimum := str(row.get("minimum_hotfix") or ""):
            return f"Apply at least hotfix {minimum}."
        return None

    def references(self, row):
        rows = row.get("cve_references")
        if not isinstance(rows, list):
            return None
        return "\n".join(str(value) for value in rows) or None

    def cwe(self, row):
        trimmed = str(row.get("cwe_id") or "").strip().upper().removeprefix("CWE-")
        with suppress(ValueError):
            return int(trimmed)
        return 0

    def tags(self, row):
        """The asset's vendor, type, product and zone, for filtering an OT estate."""
        return [
            value
            for value in (
                str(row.get(key) or "").strip()
                for key in ("node_vendor", "node_type", "node_product_name", "zone")
            )
            if value
        ]
