import json
import re
from contextlib import suppress
from datetime import datetime
from urllib.parse import urlparse

from dojo.location.feature import locations_enabled
from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

# Statuses the connector treats as not worth importing. Note "accepted_risk" is NOT here: those are
# imported and flagged risk-accepted instead, so the acceptance is recorded rather than discarded.
IGNORED_STATUSES = frozenset({"patched", "false_positive"})
STATUS_ACCEPTED_RISK = "accepted_risk"

SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "information": "Info",
    "info": "Info",
    "informational": "Info",
}
DEFAULT_SEVERITY = "Info"

# Detectify puts CVE identifiers in prose rather than a dedicated field, so they are extracted from
# every text field the connector scans.
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class DetectifyParser:

    """
    Parses a Detectify vulnerabilities export.

    Mirrors pkg/tools/detectify/connector/finding_converter.go field for field so a file import and
    an API sync deduplicate against each other instead of producing two copies of everything.

    Detectify is EASM and DAST, so every finding is dynamic and carries the affected host.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanType(). Note it does NOT follow the
        # "<Vendor> - Connectors Import" pattern the other connector scan types use.
        return ["Detectify Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Detectify Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Detectify vulnerabilities export (JSON). Matches the scan type used by the "
            "Detectify connector so file and API findings deduplicate. Findings Detectify records "
            "as patched or false positive are not imported."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Detectify Parser.

        Mirrors the connector's Convert:
        - title: Detectify's own title, then the definition's title, then the finding UUID.
        - severity: Detectify's severity word; "information" is one of its spellings.
        - description: host, location, scan source and status, then the definition's description.
        - impact: the definition's risk text.
        - mitigation: the reference links, when there are any.
        - references: the reference names and links as a markdown list.
        - cwe: Detectify reports this as a plain integer.
        - cvssv3 / cvssv3_score: the CVSS 3.1 block, falling back to 3.0.
        - risk_accepted: set when Detectify's status is accepted_risk.
        - unique_id_from_tool: the finding UUID.
        - vuln_id_from_tool: the definition's title, which is Detectify's stable rule name.
        """
        return [
            "title",
            "severity",
            "date",
            "description",
            "impact",
            "mitigation",
            "references",
            "cwe",
            "cvssv3",
            "cvssv3_score",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "tags",
            "active",
            "risk_accepted",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Detectify Parser.

        Copied from the Detectify block in the Pro connector settings, which pairs
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
            if self.is_ignored(row):
                continue
            finding = self.build_finding(row, test)
            findings.setdefault(finding.unique_id_from_tool, finding)
        return list(findings.values())

    def extract_rows(self, data):
        """Detectify's list endpoint nests the results under "vulnerabilities"."""
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
            return data["vulnerabilities"]
        msg = (
            "A Detectify export is a JSON object with a 'vulnerabilities' list, or a bare array of "
            f"vulnerabilities; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def is_ignored(self, row):
        """
        Skip findings Detectify has closed out.

        Only patched and false-positive are skipped. An accepted risk is still imported, because
        discarding it would lose the record that somebody accepted it; it is flagged instead.
        """
        return (row.get("status") or "").strip().lower() in IGNORED_STATUSES

    def build_finding(self, row, test):
        definition = row.get("definition") if isinstance(row.get("definition"), dict) else None
        score, vector = self.cvss(row.get("cvss_scores"))

        finding = Finding(
            test=test,
            title=self.title(row, definition),
            severity=SEVERITY_MAP.get(
                (row.get("severity") or "").strip().lower(), DEFAULT_SEVERITY,
            ),
            date=self.date(row.get("created_at")),
            description=self.describe(row, definition),
            impact=(definition or {}).get("risk") or None,
            mitigation=self.mitigation(row) or None,
            references=self.references(row) or None,
            cwe=row.get("cwe") or 0,
            cvssv3=vector or None,
            cvssv3_score=score or None,
            unique_id_from_tool=row.get("uuid"),
            vuln_id_from_tool=(definition or {}).get("title") or None,
            active=True,
            # Detectify is EASM and DAST: it probes running targets.
            static_finding=False,
            dynamic_finding=True,
        )
        finding.unsaved_tags = self.tags(row)

        cves = self.cves(row, definition)
        if cves:
            finding.unsaved_vulnerability_ids = cves
        if (row.get("status") or "").strip().lower() == STATUS_ACCEPTED_RISK:
            finding.risk_accepted = True

        self.attach_endpoint(finding, row)
        return finding

    def title(self, row, definition):
        if row.get("title"):
            return row["title"]
        if definition and definition.get("title"):
            return definition["title"]
        return f"Detectify finding {row.get('uuid')}"

    def describe(self, row, definition):
        """The connector's writeField() lines, then the definition's prose on its own line."""
        lines = [
            f"**{label}:** {value}" for label, value in (
                ("Host", row.get("host")),
                ("Location", row.get("location")),
                ("Scan source", row.get("scan_source")),
                ("Status", row.get("status")),
            ) if value
        ]
        if definition and definition.get("description"):
            lines.append(definition["description"])
        return "\n".join(lines).strip()

    def mitigation(self, row):
        """
        Detectify supplies no remediation text, only reference links.

        The connector points at them rather than leaving the field empty.
        """
        links = [
            ref["link"] for ref in self.references_list(row)
            if isinstance(ref, dict) and ref.get("link")
        ]
        if not links:
            return ""
        return "See references:\n" + "\n".join(links)

    def references(self, row):
        lines = []
        for ref in self.references_list(row):
            if not isinstance(ref, dict):
                continue
            name, link = ref.get("name") or "", ref.get("link") or ""
            if name and link:
                lines.append(f"- {name}: {link}")
            elif link:
                lines.append(f"- {link}")
            elif name:
                lines.append(f"- {name}")
        return "\n".join(lines)

    def references_list(self, row):
        refs = row.get("references")
        return refs if isinstance(refs, list) else []

    def cvss(self, scores):
        """
        Prefer the CVSS 3.1 block, falling back to 3.0.

        A block counts as present when it has either a score or a vector, so a vector-only entry is
        not skipped. Detectify also reports a 2.0 block, which the connector ignores because
        Finding.cvssv3 is a v3 field.
        """
        if not isinstance(scores, dict):
            return 0, ""
        for key in ("cvss_3_1", "cvss_3_0"):
            score = scores.get(key)
            if isinstance(score, dict) and ((score.get("score") or 0) > 0 or score.get("vector")):
                return score.get("score") or 0, score.get("vector") or ""
        return 0, ""

    def cves(self, row, definition):
        """
        Extract CVE identifiers from prose.

        Detectify has no dedicated CVE field, so the connector scans the title, the definition's
        title, description and risk text, and every reference name and link.
        """
        sources = [row.get("title") or ""]
        if definition:
            sources.extend([
                definition.get("title") or "",
                definition.get("description") or "",
                definition.get("risk") or "",
            ])
        for ref in self.references_list(row):
            if isinstance(ref, dict):
                sources.extend([ref.get("name") or "", ref.get("link") or ""])

        found, seen = [], set()
        for source in sources:
            for cve in CVE_PATTERN.findall(str(source)):
                upper = cve.upper()
                if upper not in seen:
                    seen.add(upper)
                    found.append(upper)
        return found

    def tags(self, row):
        tags = [
            tag["name"] for tag in (row.get("tags") or [])
            if isinstance(tag, dict) and tag.get("name")
        ]
        if row.get("scan_source"):
            tags.append(row["scan_source"])
        return tags

    def attach_endpoint(self, finding, row):
        """
        Record where the finding is, in the connector's order of preference.

        The request URL is best; otherwise the host, with the location appended when it is a path;
        otherwise the location alone.
        """
        request = row.get("request") if isinstance(row.get("request"), dict) else None
        host, location = row.get("host") or "", row.get("location") or ""

        if request and request.get("url"):
            self.add_location(finding, request["url"])
        elif host:
            self.add_location(finding, host + location if location.startswith("/") else host)
        elif location:
            self.add_location(finding, location)

    def add_location(self, finding, raw):
        """
        Record one location.

        A bare host has no scheme, so it is parsed as a protocol-relative reference to keep the value
        in the host field rather than the path - the same reason the connector prefixes "//".
        """
        with suppress(ValueError):
            parsed = urlparse(raw if "//" in raw else f"//{raw}")
            if not parsed.hostname:
                return
            data = {"host": parsed.hostname, "protocol": parsed.scheme or None, "port": parsed.port}
            path = parsed.path or None
            if locations_enabled():
                finding.unsaved_locations.append(LocationData.url(path=path, **data))
            else:
                # TODO: Delete this after the move to Locations
                finding.unsaved_endpoints.append(Endpoint(path=path.lstrip("/") if path else None, **data))

    def date(self, timestamp):
        """An RFC3339 created_at as a date; the connector leaves it unset when it will not parse."""
        if not timestamp:
            return None
        with suppress(ValueError):
            return datetime.fromisoformat(str(timestamp).strip()).date()
        return None
