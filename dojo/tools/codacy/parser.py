import json
import re
from contextlib import suppress
from datetime import UTC, datetime

from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

# Codacy grades security items by priority; the connector logs and falls back to Info for anything
# else.
SEVERITY_BY_PRIORITY = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
DEFAULT_SEVERITY = "Info"

# Codacy's scanType tells us whether the item came from a running target. Only DAST did.
SCAN_TYPE_DAST = "DAST"

# Codacy's "cve" is a typed string documented as possibly holding several identifiers, so it is
# scanned rather than read.
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
CWE_PATTERN = re.compile(r"CWE-(\d+)", re.IGNORECASE)

# An item Codacy has ignored for this reason is a false positive rather than a closed finding. The
# comparison strips spaces, so "False Positive" and "falsepositive" both match.
FALSE_POSITIVE_REASON = "falsepositive"


class CodacyParser:

    """
    Parses a Codacy security-items export.

    Mirrors pkg/tools/codacy/converter field for field so a file import and an API sync deduplicate
    against each other instead of producing two copies of everything.

    Codacy reports several scan types through one endpoint - SCA, container and DAST among them - and
    the connector flags a finding static or dynamic from that field rather than assuming.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanType().
        return ["Codacy - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Codacy - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Codacy security-items export (JSON). Matches the scan type used by the Codacy "
            "connector so file and API findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Codacy Parser.

        Mirrors the connector's ItemToFinding:
        - title: Codacy's own item title, falling back to "Codacy <scan type> - <category> item".
        - severity: the item priority, anything unrecognised Info.
        - description: the summary and additional info, then scan type, category, detector,
          repository, container image, likelihood, effort to fix and any dependency paths.
        - mitigation: Codacy's remediation advice, plus the versions the issue is fixed in.
        - references: the Codacy item link.
        - false_p: true when Codacy has ignored the item as a false positive.
        - static_finding / dynamic_finding: a DAST item is dynamic, everything else static.
        - component_name: the last entry of the first dependency chain, i.e. the vulnerable package.
        - unique_id_from_tool: Codacy's internal item id.
        - vuln_id_from_tool: the first CVE found in the item, else Codacy's own source id.
        """
        return [
            "title",
            "severity",
            "date",
            "description",
            "mitigation",
            "references",
            "cvssv3",
            "cvssv3_score",
            "cwe",
            "component_name",
            "component_version",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "tags",
            "active",
            "false_p",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Codacy Parser.

        Copied from the Codacy block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. Diverging would stop file findings
        merging with API-synced ones.
        """
        return ["title", "severity", "vuln_id_from_tool"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        items = self.extract_items(data)

        findings = {}
        for item in items:
            if not isinstance(item, dict):
                continue
            finding = self.build_finding(item, test)
            findings.setdefault(finding.unique_id_from_tool, finding)
        return list(findings.values())

    def extract_items(self, data):
        """Codacy's search endpoints wrap the items under "data"."""
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("data", "items"):
                if isinstance(data.get(key), list):
                    return data[key]
        msg = (
            "A Codacy export is a JSON object with a 'data' list of security items, or a bare "
            f"array of items; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def build_finding(self, item, test):
        dynamic = (item.get("scanType") or "").strip().upper() == SCAN_TYPE_DAST

        finding = Finding(
            test=test,
            title=self.title(item),
            severity=SEVERITY_BY_PRIORITY.get(
                (item.get("priority") or "").strip().lower(), DEFAULT_SEVERITY,
            ),
            date=self.date(item.get("openedAt")),
            description=self.describe(item),
            mitigation=self.mitigation(item) or None,
            references=item.get("htmlUrl") or None,
            cvssv3=item.get("cvssVector") or None,
            cvssv3_score=item.get("cvssScore") or None,
            component_name=self.vulnerable_package(item) or None,
            component_version=item.get("affectedVersion") or None,
            unique_id_from_tool=item.get("id"),
            vuln_id_from_tool=self.vuln_id_from_tool(item) or None,
            active=True,
            false_p=self.is_false_positive(item),
            # Only a DAST item looked at something running.
            static_finding=not dynamic,
            dynamic_finding=dynamic,
        )
        finding.unsaved_tags = self.tags(item)

        cves = self.cves(item.get("cve"))
        if cves:
            finding.unsaved_vulnerability_ids = cves
        cwe = self.cwe_number(item.get("cwe"))
        if cwe:
            finding.cwe = cwe

        self.attach_target(finding, item)
        return finding

    def attach_target(self, finding, item):
        """
        Record the scanned application or target, for the item types that have one.

        The connector emits this as an endpoint string; here the host is set directly, using the
        locations idiom so it survives under either value of V3_FEATURE_LOCATIONS.
        """
        for key in ("application", "affectedTargets"):
            target = (item.get(key) or "").strip()
            if target:
                if settings.V3_FEATURE_LOCATIONS:
                    finding.unsaved_locations.append(LocationData.url(host=target))
                else:
                    # TODO: Delete this after the move to Locations
                    finding.unsaved_endpoints.append(Endpoint(host=target))
                return

    def title(self, item):
        """Codacy's title when it has one, else a composed one, else the item id."""
        if (item.get("title") or "").strip():
            return item["title"]
        parts = [
            part for part in (item.get("scanType"), item.get("securityCategory"))
            if (part or "").strip()
        ]
        if not parts:
            return f"Codacy security item {item.get('id')}"
        return "Codacy " + " - ".join(parts) + " item"

    def vulnerable_package(self, item):
        """The last entry of the first non-empty dependency chain, as the connector does."""
        chains = item.get("dependencyChains")
        if not isinstance(chains, list):
            return ""
        for chain in chains:
            if isinstance(chain, list) and chain:
                return str(chain[-1])
        return ""

    def describe(self, item):
        sections = [
            prose.strip() for prose in (item.get("summary"), item.get("additionalInfo"))
            if (prose or "").strip()
        ]

        details = []
        for label, value in (
            ("Scan type", item.get("scanType")),
            ("Security category", item.get("securityCategory")),
            ("Detected by", item.get("itemSource")),
            ("Repository", item.get("repository")),
            ("Container image", self.container_image(item)),
            ("Likelihood", item.get("likelihood")),
            ("Effort to fix", item.get("effortToFix")),
        ):
            if (value or "").strip():
                details.append(f"**{label}:** {value}")

        chains = item.get("dependencyChains")
        if isinstance(chains, list):
            details.extend(
                "**Dependency path:** " + " → ".join(str(c) for c in chain)
                for chain in chains if isinstance(chain, list) and chain
            )

        if details:
            sections.append("\n".join(details))
        return "\n\n".join(sections)

    def container_image(self, item):
        name = (item.get("imageName") or "").strip()
        if not name:
            return ""
        tag = (item.get("imageTag") or "").strip()
        return f"{name}:{tag}" if tag else name

    def mitigation(self, item):
        parts = []
        if (item.get("remediation") or "").strip():
            parts.append(item["remediation"].strip())
        fixed = item.get("fixedVersion")
        if isinstance(fixed, list):
            versions = [str(v).strip() for v in fixed if str(v).strip()]
            if versions:
                parts.append("Fixed in: " + ", ".join(versions))
        return "\n\n".join(parts)

    def vuln_id_from_tool(self, item):
        """The first CVE in the item, upper-cased, else Codacy's own source id."""
        match = CVE_PATTERN.search(item.get("cve") or "")
        if match:
            return match.group(0).upper()
        return item.get("itemSourceId") or ""

    def cves(self, raw):
        """Codacy's cve field can hold several identifiers; take them all, deduplicated."""
        found = CVE_PATTERN.findall(raw or "")
        ids, seen = [], set()
        for cve in found:
            upper = cve.upper()
            if upper not in seen:
                seen.add(upper)
                ids.append(upper)
        return ids

    def cwe_number(self, raw):
        match = CWE_PATTERN.search(raw or "")
        if not match:
            return 0
        with suppress(ValueError):
            return int(match.group(1))
        return 0

    def is_false_positive(self, item):
        """
        Codacy can ignore an item, and the reason says whether it was a false positive.

        The comparison strips spaces so "False Positive" and "falsepositive" both match; any other
        ignore reason is not a false positive.
        """
        ignored = item.get("ignored")
        if not isinstance(ignored, dict):
            return False
        reason = (ignored.get("reason") or "").strip().lower().replace(" ", "")
        return reason == FALSE_POSITIVE_REASON

    def tags(self, item):
        return [
            value.strip() for value in
            (item.get("scanType"), item.get("securityCategory"), item.get("itemSource"))
            if (value or "").strip()
        ]

    def date(self, timestamp):
        """
        Codacy's openedAt as a date.

        The connector falls back to today when the timestamp will not parse, so that a finding always
        carries a date; that is mirrored here.
        """
        with suppress(ValueError, AttributeError):
            return datetime.fromisoformat((timestamp or "").strip()).astimezone(UTC).date()
        return datetime.now(tz=UTC).date()
