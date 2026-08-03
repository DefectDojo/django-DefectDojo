import json
import re
from datetime import UTC, datetime

from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

# Halo Security grades severity as an INTEGER level, 5 highest. Level 1 and 0 both mean Info - 0
# appears in scan counts rather than on a real issue.
SEVERITY_BY_LEVEL = {5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Info", 0: "Info"}
DEFAULT_SEVERITY = "Info"

STATUS_CONFIRMED = "confirmed"
STATUS_FIXING = "fixing"
STATUS_FIXED = "fixed"
STATUS_ACK_FALSE_POSITIVE = "ack_false_positive"
STATUS_ACK_ACCEPTABLE_RISK = "ack_acceptable_risk"

# Halo Security uses this literal to mean "unassigned", so it is not worth reporting.
UNASSIGNED = "nobody"

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class HaloSecurityParser:

    """
    Parses a Halo Security issues export.

    Mirrors pkg/tools/halosecurity/converter field for field so a file import and an API sync
    deduplicate against each other instead of producing two copies of everything.

    Halo Security splits an issue across two calls: a list row carrying the issue, target and status,
    and a per-issue detail carrying the description, category, CVEs and PCI flag. An export needs both
    to produce a complete finding - see detail_for().

    Note the deduplication configuration for this scan type hashes the ENDPOINTS, so the target has to
    be populated or the hash is computed over nothing.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanType().
        return ["Halo Security - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Halo Security - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Halo Security issues export (JSON). Matches the scan type used by the Halo "
            "Security connector so file and API findings deduplicate. Include the per-issue details "
            "so findings carry their description, category and CVEs."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Halo Security Parser.

        Mirrors the connector's RowToFinding:
        - title: the issue name from the row, then from the detail, then "Halo Security issue <id>".
        - severity: the integer severity level, 5 highest; see severity().
        - description: the detail's description, then target, status, category, PCI, assignee and the
          number of scans the issue has persisted for.
        - active / is_mitigated / false_p / risk_accepted / verified: from the row's status.
        - unique_id_from_tool: "<issue id>:<target id>" - one issue on two hosts is two findings.
        - vuln_id_from_tool: the issue id, which is Halo's rule identifier.
        """
        return [
            "title",
            "severity",
            "date",
            "description",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "tags",
            "active",
            "is_mitigated",
            "false_p",
            "risk_accepted",
            "verified",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Halo Security Parser.

        Copied from the Halo Security block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. Note endpoints is among them, so the
        target must be populated for the hash to mean anything.
        """
        return ["title", "severity", "endpoints"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        rows, details = self.extract(data)

        findings = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            issue = row.get("issue")
            if not isinstance(issue, dict):
                # The connector skips a row with no issue block at all.
                continue
            finding = self.build_finding(row, issue, self.detail_for(row, issue, details), test)
            findings.setdefault(finding.unique_id_from_tool, finding)
        return list(findings.values())

    def extract(self, data):
        """
        Return the issue rows and any per-issue details.

        Halo's issue list nests rows under "list". The details come from a second endpoint, so an
        export carries them either as a top-level "details" map or array keyed by issue id, or nested
        on each row as "detail".
        """
        details = {}
        rows = None

        if isinstance(data, list):
            rows = data
        elif isinstance(data, dict):
            for key in ("list", "issues", "rows"):
                if isinstance(data.get(key), list):
                    rows = data[key]
                    break
            details = self.index_details(data.get("details"))

        if rows is None:
            msg = (
                "A Halo Security export is the issue-list response, a JSON object with a 'list' of "
                f"issue rows; got {type(data).__name__}."
            )
            raise TypeError(msg)
        return rows, details

    def index_details(self, source):
        """Accept the details as a map keyed by issue id, or as a plain array of detail objects."""
        indexed = {}
        if isinstance(source, dict):
            for key, value in source.items():
                detail = value.get("issue") if isinstance(value, dict) and "issue" in value else value
                if isinstance(detail, dict):
                    indexed[str(key)] = detail
        elif isinstance(source, list):
            for value in source:
                detail = value.get("issue") if isinstance(value, dict) and "issue" in value else value
                if isinstance(detail, dict) and detail.get("issue_id") is not None:
                    indexed[str(detail["issue_id"])] = detail
        return indexed

    def detail_for(self, row, issue, details):
        """The detail nested on the row, else the one indexed by this row's issue id."""
        nested = row.get("detail")
        if isinstance(nested, dict):
            return nested.get("issue") if isinstance(nested.get("issue"), dict) else nested
        return details.get(str(issue.get("issue_id")), {})

    def build_finding(self, row, issue, detail, test):
        status_block = row.get("status") if isinstance(row.get("status"), dict) else {}
        status = (status_block.get("status") or "").strip().lower()
        unique_id = self.unique_id(row, issue, status_block)

        false_positive = status == STATUS_ACK_FALSE_POSITIVE
        risk_accepted = status == STATUS_ACK_ACCEPTABLE_RISK
        mitigated = status == STATUS_FIXED

        finding = Finding(
            test=test,
            title=self.title(issue, detail, unique_id),
            severity=self.severity(issue, detail),
            # The connector stamps today's date; Halo's list response carries no discovery date.
            date=datetime.now(tz=UTC).date(),
            description=self.describe(row, detail, status_block),
            unique_id_from_tool=unique_id,
            vuln_id_from_tool=str(issue["issue_id"]) if issue.get("issue_id") is not None else None,
            active=not (mitigated or false_positive or risk_accepted),
            is_mitigated=mitigated,
            false_p=false_positive,
            risk_accepted=risk_accepted,
            # Only these three states mean a human has confirmed the issue is real.
            verified=status in {STATUS_CONFIRMED, STATUS_FIXING, STATUS_FIXED},
            # Halo Security probes live hosts.
            static_finding=False,
            dynamic_finding=True,
        )
        finding.unsaved_tags = self.tags(detail, status_block)

        cves = self.cves(detail)
        if cves:
            finding.unsaved_vulnerability_ids = cves

        self.attach_target(finding, row)
        return finding

    def unique_id(self, row, issue, status_block):
        """
        "<issue id>:<target id>".

        The target is part of the identity because Halo reports the same issue once per affected host;
        keying on the issue alone would collapse them into one finding.
        """
        issue_id = issue.get("issue_id") or 0
        target_id = status_block.get("target_id") or 0
        if not target_id:
            target = row.get("target")
            if isinstance(target, dict):
                target_id = target.get("target_id") or 0
        return f"{issue_id}:{target_id}"

    def title(self, issue, detail, unique_id):
        name = (issue.get("name") or "").strip()
        if name:
            return name
        detail_name = (detail.get("name") or "").strip()
        if detail_name:
            return detail_name
        return f"Halo Security issue {unique_id}"

    def severity(self, issue, detail):
        """
        Grade Halo's integer level.

        The row's level wins when set; the detail's is the fallback, because the list response
        sometimes omits it. A level outside 0-5 is Info.
        """
        level = issue.get("severity") or 0
        if not level:
            level = detail.get("severity") or 0
        return SEVERITY_BY_LEVEL.get(level, DEFAULT_SEVERITY)

    def describe(self, row, detail, status_block):
        sections = []
        description = (detail.get("description") or "").strip()
        if description:
            sections.append(description)

        details = []

        def add(label, value):
            text = str(value).strip() if value is not None else ""
            if text:
                details.append(f"**{label}:** {text}")

        add("Target", self.target(row))
        add("Halo status", status_block.get("status"))
        add("Category", detail.get("category"))
        if detail.get("pci") == 1:
            add("PCI", "this issue affects PCI compliance")
        assigned = (status_block.get("assigned_to") or "").strip()
        if assigned and assigned.lower() != UNASSIGNED:
            add("Assigned to", assigned)
        if status_block:
            # Reported even when zero, since the connector formats the integer unconditionally.
            add("Scans since found", status_block.get("scans_since_found") or 0)

        if details:
            sections.append("\n".join(details))
        return "\n\n".join(sections)

    def tags(self, detail, status_block):
        tags = []
        category = (detail.get("category") or "").strip()
        if category:
            tags.append(category)
        if detail.get("pci") == 1:
            tags.append("pci")
        status = (status_block.get("status") or "").strip()
        if status:
            tags.append(status)
        return tags

    def cves(self, detail):
        """Halo lists CVEs on the detail; the values are scanned so a joined string also works."""
        raw = detail.get("cve_ids")
        if isinstance(raw, str):
            candidates = [raw]
        elif isinstance(raw, list):
            candidates = [str(item) for item in raw]
        else:
            return []

        found, seen = [], set()
        for candidate in candidates:
            for cve in CVE_PATTERN.findall(candidate):
                upper = cve.upper()
                if upper not in seen:
                    seen.add(upper)
                    found.append(upper)
        return found

    def target(self, row):
        target = row.get("target")
        return (target.get("target") or "").strip() if isinstance(target, dict) else ""

    def attach_target(self, finding, row):
        """
        Record the scanned host.

        This scan type's deduplication hashes the endpoints, so leaving it unpopulated would leave the
        hash computed over nothing and every rescan would reimport.
        """
        host = self.target(row)
        if not host:
            return
        host = host.split("//")[-1].split("/")[0]
        if not host:
            return
        if settings.V3_FEATURE_LOCATIONS:
            finding.unsaved_locations.append(LocationData.url(host=host))
        else:
            # TODO: Delete this after the move to Locations
            finding.unsaved_endpoints.append(Endpoint(host=host))
