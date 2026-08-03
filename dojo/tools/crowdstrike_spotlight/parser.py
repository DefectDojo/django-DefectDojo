import json
from contextlib import suppress
from datetime import datetime

from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

# Mirrors mapCVESeverity() in the CrowdStrike connector's vuln_converter: the comparison is on the
# upper-cased CVE severity, and anything unrecognised becomes Info.
SEVERITY_MAP = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
}
DEFAULT_SEVERITY = "Info"


class CrowdstrikeSpotlightParser:

    """
    Parses a CrowdStrike Falcon Spotlight vulnerability export.

    Mirrors pkg/tools/crowdstrike/connector/vuln_converter.go field for field, so that a file import
    and an API sync produce findings that deduplicate against each other rather than two copies of
    everything.

    Note that the connector marks these findings NEITHER static NOR dynamic. Spotlight reports
    vulnerable software present on a host from the agent's inventory; it does not analyse source and
    it does not probe a running service. The connector's choice is mirrored rather than corrected.
    """

    def get_scan_types(self):
        # Byte-identical to ScanTypeSpotlight in the connector. The connector also defines
        # "CrowdStrike:Detections - Connectors Import", which is a different shape and not this
        # parser's concern.
        return ["CrowdStrike:Spotlight - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "CrowdStrike:Spotlight - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a CrowdStrike Falcon Spotlight vulnerability export (JSON). Matches the scan "
            "type used by the CrowdStrike Spotlight connector so file and API findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the CrowdStrike Spotlight Parser.

        Mirrors the connector's VulnConverter.Convert:
        - title: "<CVE>: <product and version>", degrading as the converter's title() does.
        - severity: the CVE severity, anything unrecognised Info.
        - severity_justification: the converter's sentence about severity, score and ExPRT rating.
        - description: CVE description, then host, OS, affected product, ExPRT rating and CISA KEV.
        - mitigation: each remediation entity's title, action and reference.
        - references: CVE references, vendor advisories, and each entity's link and vendor URL.
        - cvssv3 / cvssv3_score: the CVE vector and base score.
        - cwe: the first parseable CWE-NNN.
        - component_name / component_version: the first app's normalized name, and the version
          derived by stripping that name from its product_name_version.
        - unique_id_from_tool: the Spotlight vulnerability id.
        - vuln_id_from_tool: the CVE id.
        """
        return [
            "title",
            "severity",
            "severity_justification",
            "description",
            "mitigation",
            "references",
            "date",
            "cvssv3",
            "cvssv3_score",
            "cwe",
            "component_name",
            "component_version",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "tags",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the CrowdStrike Spotlight Parser.

        Copied from the CrowdStrike Spotlight block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. Diverging would stop file findings
        merging with API-synced ones.
        """
        return ["unique_id_from_tool", "title", "severity", "vulnerability_ids"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        rows = self.extract_rows(data)

        findings = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            finding = self.build_finding(row, test)
            # The Spotlight vulnerability id is the connector's identity.
            findings.setdefault(finding.unique_id_from_tool, finding)
        return list(findings.values())

    def extract_rows(self, data):
        """The Falcon API wraps results under "resources"; a saved export is often the bare array."""
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("resources", "vulnerabilities"):
                if isinstance(data.get(key), list):
                    return data[key]
        msg = (
            "A CrowdStrike Spotlight export is a JSON array of vulnerabilities, or an object with "
            f"a 'resources' list; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def build_finding(self, row, test):
        cve = row.get("cve") or {}
        host = row.get("host_info") or {}
        apps = row.get("apps") or []
        app = apps[0] if apps and isinstance(apps[0], dict) else {}

        cve_id = cve.get("id") or ""
        base_score = cve.get("base_score") or 0

        finding = Finding(
            test=test,
            title=self.title(cve_id, self.product(app)),
            severity=self.severity(cve),
            severity_justification=self.justification(cve, base_score),
            description=self.describe(cve, host, app),
            mitigation=self.mitigation(row) or None,
            references=self.references(row, cve) or None,
            date=self.date(row.get("created_timestamp")),
            cvssv3=cve.get("vector") or None,
            cvssv3_score=base_score or None,
            cwe=self.first_cwe(cve.get("cwes")),
            component_name=app.get("product_name_normalized") or None,
            component_version=self.component_version(app) or None,
            unique_id_from_tool=row.get("id"),
            vuln_id_from_tool=cve_id or None,
            # The converter sets both to false: Spotlight reads an agent's software inventory, so it
            # neither analyses source nor probes a running service.
            static_finding=False,
            dynamic_finding=False,
        )
        finding.unsaved_tags = self.tags(cve, host)
        if cve_id:
            finding.unsaved_vulnerability_ids = [cve_id]

        self.attach_host(finding, host)
        return finding

    def attach_host(self, finding, host):
        """
        Record the affected host.

        The connector emits a protocol-relative "//<host>" string because DefectDojo parses a bare
        hostname as a URL path. Here the host is set directly instead, which is the same outcome
        without the string round-trip.
        """
        name = host.get("hostname") or host.get("local_ip")
        if not name:
            return
        if settings.V3_FEATURE_LOCATIONS:
            finding.unsaved_locations.append(LocationData.url(host=name))
        else:
            # TODO: Delete this after the move to Locations
            finding.unsaved_endpoints.append(Endpoint(host=name))

    def title(self, cve_id, product):
        """Build the title as the converter does: CVE and product, then either alone, then a constant."""
        if cve_id and product:
            return f"{cve_id}: {product}"
        if cve_id:
            return cve_id
        if product:
            return product
        return "CrowdStrike Spotlight Vulnerability"

    def product(self, app):
        """Take the versioned product name, falling back to the plain one, as the converter does."""
        return app.get("product_name_version") or app.get("product_name_normalized") or ""

    def component_version(self, app):
        """
        Converter componentVersion().

        CrowdStrike returns no discrete version field, so the version is whatever is left of
        product_name_version once the normalized product name is stripped from the front.
        """
        normalized = app.get("product_name_normalized") or ""
        versioned = app.get("product_name_version") or ""
        if normalized and versioned.startswith(normalized):
            return versioned[len(normalized):].strip()
        return ""

    def severity(self, cve):
        return SEVERITY_MAP.get((cve.get("severity") or "").strip().upper(), DEFAULT_SEVERITY)

    def justification(self, cve, base_score):
        """Converter severityJustification(), including its markdown emphasis and score format."""
        justification = f"CrowdStrike severity of **{cve.get('severity') or ''}**"
        if base_score:
            justification += f" from a base CVSS score of **{base_score:.1f}**"
        if cve.get("exprt_rating"):
            justification += f" (ExPRT rating: {cve['exprt_rating']})"
        return justification

    def describe(self, cve, host, app):
        parts = []
        if cve.get("description"):
            parts.append(cve["description"] + "\n")

        lines = []
        if host.get("hostname"):
            lines.append(f"**Host:** {host['hostname']}")
        if host.get("os_version"):
            lines.append(f"**OS:** {host['os_version']}")
        if product := self.product(app):
            lines.append(f"**Affected product:** {product}")
        if cve.get("exprt_rating"):
            lines.append(f"**ExPRT rating:** {cve['exprt_rating']}")
        if (cve.get("cisa_info") or {}).get("is_cisa_kev"):
            lines.append(
                "**CISA KEV:** listed in the CISA Known Exploited Vulnerabilities catalog",
            )
        parts.extend(lines)
        return "\n".join(parts).strip()

    def mitigation(self, row):
        """Build one block per remediation entity, with a blank line between blocks."""
        blocks = []
        for entity in self.entities(row):
            parts = []
            if entity.get("title"):
                parts.append(f"**{entity['title']}**")
            if entity.get("action"):
                parts.append(entity["action"])
            if entity.get("reference"):
                parts.append(f"Reference: {entity['reference']}")
            if parts:
                blocks.append("\n".join(parts))
        return "\n\n".join(blocks)

    def references(self, row, cve):
        """Collect CVE references, then vendor advisories, then each entity's links."""
        refs = []
        for key in ("references", "vendor_advisory"):
            value = cve.get(key)
            if isinstance(value, list):
                refs.extend(str(item) for item in value if item)
        for entity in self.entities(row):
            refs.extend(entity[key] for key in ("link", "vendor_url") if entity.get(key))
        return "\n".join(refs)

    def entities(self, row):
        entities = (row.get("remediation") or {}).get("entities")
        return [e for e in entities if isinstance(e, dict)] if isinstance(entities, list) else []

    def tags(self, cve, host):
        tags = []
        if cve.get("exprt_rating"):
            tags.append(f"exprt:{cve['exprt_rating'].lower()}")
        if (cve.get("cisa_info") or {}).get("is_cisa_kev"):
            tags.append("cisa-kev")
        host_tags = host.get("tags")
        if isinstance(host_tags, list):
            tags.extend(str(tag) for tag in host_tags if tag)
        return tags

    def first_cwe(self, cwes):
        """Converter firstCWE(): the first "CWE-NNN" that parses, else 0."""
        if not isinstance(cwes, list):
            return 0
        for cwe in cwes:
            parts = str(cwe).split("-")
            if len(parts) != 2:
                continue
            with suppress(ValueError):
                return int(parts[1])
        return 0

    def date(self, timestamp):
        """Converter formatDate(): an RFC3339 timestamp as a date, or nothing if it will not parse."""
        if not timestamp:
            return None
        text = str(timestamp).replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(text).date()
        except ValueError:
            return None
