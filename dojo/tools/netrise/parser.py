import json
from contextlib import suppress

from dojo.models import Finding

SEVERITY_BY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "informational": "Info",
    "none": "Info",
}


class NetriseParser:

    """
    Parses a NetRise firmware-analysis export.

    Mirrors pkg/tools/netrise/connector/finding_converter field for field so a file import and an API
    sync deduplicate against each other instead of producing two copies of everything.

    NetRise answers GraphQL in Relay shape - a list of {"node": {...}} edges - and serves the firmware
    artifacts and each artifact's vulnerabilities from separate queries, so an export carries both and
    the edges are unwrapped; see rows(). The artifact matters to the finding: the identity is scoped to
    it, so the same CVE in two firmware builds stays two findings.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName. Note it does NOT follow the
        # "<Vendor> - Connectors Import" pattern, so it cannot be derived - it has to be copied.
        return ["NetRise Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "NetRise Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a NetRise export (JSON) - a firmware artifact with its vulnerabilities, in the "
            "GraphQL Relay shape NetRise answers with. Matches the scan type used by the NetRise "
            "connector so file and API findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the NetRise Parser.

        Mirrors the connector's Convert:
        - title: "<CVE> in <component>", or whichever of the two is present.
        - severity: NetRise's severity word, falling back to its CVSS score; see severity().
        - severity_justification: reachability and CISA KEV listing, spelled out.
        - description: the component, the artifact and its vendor, product and firmware version.
        - mitigation: upgrade to a fixed version, when NetRise names one.
        - component_name / cvssv3_score: the affected component and the CVSS base score.
        - unique_id_from_tool: "netrise-<artifact id>-<CVE or component>".
        """
        return [
            "title",
            "severity",
            "severity_justification",
            "description",
            "mitigation",
            "component_name",
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
        Return the list of fields used for deduplication in the NetRise Parser.

        Copied from the NetRise block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields.
        """
        return ["title", "severity", "component_name"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        asset = self.asset(data)
        return [
            self.build_finding(row, self.block(row, "asset") or asset, test)
            for row in self.rows(data)
        ]

    def rows(self, data):
        """
        Return the vulnerabilities in the export.

        NetRise answers GraphQL Relay: {"vulnerabilities": {"edges": [{"node": {...}}]}}. The edges are
        unwrapped, and a plain list of vulnerabilities is accepted too - so an export somebody has
        already flattened still imports.
        """
        if isinstance(data, list):
            return self.nodes(data)

        if isinstance(data, dict):
            for holder in (self.block(data, "data"), data):
                for key in ("vulnerabilities", "allVulnerabilities", "findings"):
                    value = holder.get(key)
                    if isinstance(value, dict) and isinstance(value.get("edges"), list):
                        return self.nodes(value["edges"])
                    if isinstance(value, list):
                        return self.nodes(value)

        msg = (
            "A NetRise export is the vulnerabilities response, a JSON object with a "
            f"'vulnerabilities' object or list; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def nodes(self, rows):
        """Unwrap Relay edges, accepting rows that are already the node itself."""
        unwrapped = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            node = row.get("node")
            unwrapped.append(node if isinstance(node, dict) else row)
        return unwrapped

    def asset(self, data):
        """
        The firmware artifact the whole file belongs to.

        One export is one artifact, so it is stated once for the file - though a row carrying its own
        overrides it. The artifact is what the identity is scoped to, so the same CVE in two firmware
        builds stays two findings rather than merging into one.
        """
        if not isinstance(data, dict):
            return {}
        for holder in (data, self.block(data, "data")):
            for key in ("asset", "artifact"):
                if candidate := self.block(holder, key):
                    return candidate
            relay = self.block(holder, "assetsRelay")
            if isinstance(relay.get("edges"), list):
                nodes = self.nodes(relay["edges"])
                if nodes:
                    return nodes[0]
        return {}

    def block(self, row, key):
        if not isinstance(row, dict):
            return {}
        value = row.get(key)
        return value if isinstance(value, dict) else {}

    def build_finding(self, row, asset, test):
        cve = str(row.get("cve") or "")
        component = str(row.get("name") or "")

        finding = Finding(
            test=test,
            title=self.title(cve, component),
            severity=self.severity(row),
            description=self.describe(row, asset, component),
            mitigation=self.mitigation(row),
            component_name=component or None,
            unique_id_from_tool=f"netrise-{asset.get('id') or ''}-{cve or component}",
            vuln_id_from_tool=cve or None,
            # Firmware analysis inspects an artifact without running it.
            static_finding=True,
            dynamic_finding=False,
            active=True,
        )
        finding.cvssv3_score = self.score(row)
        finding.unsaved_tags = self.tags(row, asset)

        if cve:
            finding.unsaved_vulnerability_ids = [cve]
        if justification := self.justification(row):
            finding.severity_justification = justification
        return finding

    def title(self, cve, component):
        if cve and component:
            return f"{cve} in {component}"
        if cve:
            return cve
        if component:
            return component
        return "NetRise vulnerability"

    def severity(self, row):
        """
        NetRise's severity word, falling back to its CVSS score.

        An unrecognised word falls through to the SCORE rather than to Info, so a finding NetRise
        grades with a word this parser does not know still lands at the severity its score implies.
        """
        label = str(row.get("severity") or "").strip().lower()
        if label in SEVERITY_BY_LABEL:
            return SEVERITY_BY_LABEL[label]

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
        """NetRise's CVSS base score, which may arrive quoted."""
        value = row.get("cvssScore")
        if isinstance(value, bool) or value is None:
            return 0.0
        if isinstance(value, int | float):
            return float(value)
        if isinstance(value, str):
            with suppress(ValueError):
                return float(value.strip() or 0)
        return 0.0

    def describe(self, row, asset, component):
        lines = []

        def write(label, value):
            # The connector tests for emptiness WITHOUT trimming, which a plain truthiness test
            # reproduces exactly for strings.
            if value:
                lines.append(f"**{label}:** {value}")

        write("Component", component)
        write("Artifact", str(asset.get("name") or ""))
        write("Vendor", str(asset.get("vendor") or ""))
        write("Product", str(asset.get("product") or ""))
        write("Firmware version", str(asset.get("version") or ""))

        if row.get("isReachable"):
            write("Reachable", "yes")
        if row.get("inKnownExploitedVulnerabilities"):
            write("CISA KEV", "yes")
        return "\n".join(lines).strip()

    def mitigation(self, row):
        versions = [str(value) for value in row.get("fixVersions") or []]
        if versions:
            return "Upgrade to a fixed version: " + ", ".join(versions) + "."
        return None

    def justification(self, row):
        """
        Reachability and CISA KEV listing, spelled out.

        Both are recorded as the justification rather than moving the severity: a reachable,
        actively-exploited flaw in firmware is more urgent than its score says, and a reviewer needs
        to see why - but changing the grade would make it disagree with an API sync.
        """
        notes = []
        if row.get("isReachable"):
            notes.append("NetRise marks this vulnerability as reachable in the firmware.")
        if row.get("inKnownExploitedVulnerabilities"):
            notes.append("Listed in CISA's Known Exploited Vulnerabilities catalog.")
        return " ".join(notes)

    def tags(self, row, asset):
        """The artifact's vendor and product, plus reachability and KEV markers, for filtering."""
        tags = [
            value
            for value in (str(asset.get("vendor") or "").strip(), str(asset.get("product") or "").strip())
            if value
        ]
        if row.get("isReachable"):
            tags.append("reachable")
        if row.get("inKnownExploitedVulnerabilities"):
            tags.append("cisa-kev")
        return tags
