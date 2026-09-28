import json
import re
from contextlib import suppress
from datetime import UTC, datetime

from dojo.models import Finding

# VMP grades on Microsoft's MSRC scale, whose names do not match DefectDojo's: "Important" is High and
# "Moderate" is Medium. Reading them as literal DefectDojo names would drop both a tier.
SEVERITY_BY_LABEL = {
    "critical": "Critical",
    "important": "High",
    "high": "High",
    "moderate": "Medium",
    "medium": "Medium",
    "low": "Low",
}
# "Unrated" and anything unrecognised land here.
DEFAULT_SEVERITY = "Info"

# Statuses that mean the vulnerability has been dealt with.
CLOSED_STATUSES = {"close", "closed", "fixed", "remediated"}

# The advisory identifiers the connector's shared extractor recognises in free text.
VULNERABILITY_ID_PATTERN = re.compile(
    r"CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|GO-\d{4}-\d+|RHSA-\d{4}:\d+",
)


class VmanplusParser:

    """
    Parses a ManageEngine Vulnerability Manager Plus export.

    Mirrors pkg/tools/vmanplus/connector/finding_converter field for field so a file import and an API
    sync deduplicate against each other instead of producing two copies of everything.

    VMP grades on Microsoft's MSRC scale, where "Important" and "Moderate" mean High and Medium - names
    that would each drop a tier if read as DefectDojo's own; see severity().

    Its rows are already fused: each carries both the vulnerability and the asset it was found on, so
    nothing has to be joined.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName. Note it does NOT follow the
        # "<Vendor> - Connectors Import" pattern, so it cannot be derived - it has to be copied.
        return ["ManageEngine Vulnerability Manager Plus Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "ManageEngine Vulnerability Manager Plus Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a ManageEngine Vulnerability Manager Plus export (JSON), each row carrying the "
            "vulnerability and the asset it was found on. Matches the scan type used by the VMP "
            "connector so file and API findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the VMP Parser.

        Mirrors the connector's Convert:
        - title: the vulnerability name, then its CVE ids, then the vulnerability id.
        - severity: VMP's MSRC-style severity word; see severity().
        - description: the vulnerability, its CVE ids, the host, its address and the status.
        - mitigation: the patch description and the patch id.
        - cvssv3_score: the CVSS v3 score, falling back to v2.
        - component_name: the host, named by resource name, FQDN, or address.
        - active: false once VMP reports the vulnerability closed; see is_open().
        - date: the row's update time, in epoch MILLIseconds.
        - unique_id_from_tool: "vmanplus-<resource id>-<vulnerability id>".
        """
        return [
            "title",
            "severity",
            "description",
            "mitigation",
            "cvssv3_score",
            "component_name",
            "references",
            "date",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "unsaved_vulnerability_ids",
            "active",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the VMP Parser.

        Copied from the ManageEngine Vulnerability Manager Plus block in the Pro connector settings,
        which pairs unique_id_from_tool_or_hash_code with these hash fields. The HOST is the component
        here, not a package, so the same vulnerability on two machines stays two findings.
        """
        return ["title", "severity", "component_name"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        return [self.build_finding(row, test) for row in self.rows(data)]

    def rows(self, data):
        """
        Return the vulnerability rows in the export.

        VMP answers {"vulnerabilities": [...]} alongside its paging metadata, so that is the shape a
        saved export has. A bare array is accepted too.
        """
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
        if isinstance(data, dict):
            for key in ("vulnerabilities", "data", "results"):
                if isinstance(data.get(key), list):
                    return [row for row in data[key] if isinstance(row, dict)]

        msg = (
            "A ManageEngine Vulnerability Manager Plus export is a JSON object with a "
            f"'vulnerabilities' list; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def build_finding(self, row, test):
        host = self.host(row)
        cve_ids = str(row.get("cveids") or "")

        finding = Finding(
            test=test,
            title=self.title(row, cve_ids),
            severity=self.severity(row),
            description=self.describe(row, host, cve_ids),
            mitigation=self.mitigation(row) or None,
            component_name=host or None,
            references=str(row.get("reference_links") or "") or None,
            unique_id_from_tool=(
                f"vmanplus-{self.text(row.get('resource_id'))}-"
                f"{self.text(row.get('vulnerabilityid'))}"
            ),
            vuln_id_from_tool=self.text(row.get("vulnerabilityid")) or None,
            # VMP compares an installed inventory against advisories; nothing is exercised.
            static_finding=True,
            dynamic_finding=False,
            active=self.is_open(row),
        )
        finding.cvssv3_score = self.score(row)

        if identifiers := self.vulnerability_ids(cve_ids):
            finding.unsaved_vulnerability_ids = identifiers
        if date := self.date(row):
            finding.date = date
        return finding

    def title(self, row, cve_ids):
        if name := str(row.get("vulnerabilityname") or ""):
            return name
        if cve_ids:
            return cve_ids
        return f"ManageEngine VMP vulnerability {self.text(row.get('vulnerabilityid'))}"

    def severity(self, row):
        """
        VMP's MSRC-style severity word.

        "Important" is High and "Moderate" is Medium - DefectDojo has neither name, so reading them
        literally would fall through to Info and drop both a tier. "Unrated" is Info.
        """
        label = str(row.get("severity") or "").strip().lower()
        return SEVERITY_BY_LABEL.get(label, DEFAULT_SEVERITY)

    def score(self, row):
        """The CVSS v3 score, falling back to v2 - VMP reports both for older advisories."""
        for key in ("cvss_3_score", "cvss_2_score"):
            if (score := self.number(row.get(key))) > 0:
                return score
        return 0.0

    def host(self, row):
        """The machine, named by its resource name, then its FQDN, then its address."""
        for key in ("resource_name", "fqdn_name", "ip_address"):
            if value := str(row.get(key) or "").strip():
                return value
        return ""

    def is_open(self, row):
        """A vulnerability stays active until VMP reports it closed, fixed or remediated."""
        return str(row.get("vulnerability_status") or "").strip().lower() not in CLOSED_STATUSES

    def describe(self, row, host, cve_ids):
        lines = []

        def write(label, value):
            if str(value or "").strip():
                lines.append(f"**{label}:** {value}")

        write("Vulnerability", str(row.get("vulnerabilityname") or ""))
        write("CVE IDs", cve_ids)
        write("Host", host)
        write("IP address", str(row.get("ip_address") or ""))
        write("Status", str(row.get("vulnerability_status") or ""))
        return "\n".join(lines).strip()

    def mitigation(self, row):
        """The patch VMP would deploy, and its id - the two things needed to act on the finding."""
        lines = []
        for label, key in (("Patch", "patch_description"), ("Patch ID", "patchid")):
            if value := self.text(row.get(key)):
                lines.append(f"**{label}:** {value}")
        return "\n".join(lines).strip()

    def vulnerability_ids(self, cve_ids):
        """
        Identifiers read out of the CVE id field, which VMP sends as ONE string.

        It may hold several, so they are extracted rather than used whole. The connector's shared
        extractor sorts its results and drops case-insensitive duplicates.
        """
        matches = sorted(VULNERABILITY_ID_PATTERN.findall(cve_ids))
        identifiers = []
        for match in matches:
            # Adjacent-only dedupe after the sort, which is what slices.CompactFunc does.
            if not identifiers or identifiers[-1].lower() != match.lower():
                identifiers.append(match)
        return identifiers

    def date(self, row):
        """VMP timestamps in epoch MILLIseconds; reading them as seconds would date everything to 1970."""
        value = self.integer(row.get("updatedtime"))
        if value <= 0:
            return None
        with suppress(OSError, OverflowError, ValueError):
            return datetime.fromtimestamp(value / 1000, tz=UTC).date()
        return None

    def text(self, value):
        """
        VMP's ids are strings that may arrive as JSON numbers.

        Its own decoder accepts either, and an id read as a float would render as "1.0" and never match
        the API's "1".
        """
        if value is None or isinstance(value, bool):
            return ""
        if isinstance(value, float) and value.is_integer():
            return str(int(value))
        if isinstance(value, int | float):
            return str(value)
        return str(value).strip()

    def number(self, value):
        if isinstance(value, bool) or value is None:
            return 0.0
        if isinstance(value, int | float):
            return float(value)
        if isinstance(value, str):
            with suppress(ValueError):
                return float(value.strip() or 0)
        return 0.0

    def integer(self, value):
        return int(self.number(value))
