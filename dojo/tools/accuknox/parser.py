import json
import re
from contextlib import suppress
from datetime import datetime

from dojo.models import Finding

# AccuKnox grades by "risk factor". Anything else, including an empty value, is Info.
SEVERITY_BY_RISK_FACTOR = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
DEFAULT_SEVERITY = "Info"

STATUS_POTENTIAL = "potential"
STATUS_ACCEPTED_RISK = "accepted risk"
STATUS_DUPLICATE = "duplicate"
STATUS_FIXED = "fixed"

# AccuKnox covers container, IaC, cloud-posture and runtime findings through one endpoint, and the
# row keys differ per data type. The connector probes a list of candidate names for each field
# rather than assuming one schema, because AccuKnox does not publish this part of it.
ID_FIELDS = ("finding_id", "id", "uuid")
TITLE_FIELDS = ("name", "title", "finding_name", "vulnerability_name")
DATA_TYPE_FIELDS = ("data_type",)
SEVERITY_FIELDS = ("risk_factor", "severity")
STATUS_FIELDS = ("status", "finding_status")
DESCRIPTION_FIELDS = ("description", "details", "summary", "message")
SOLUTION_FIELDS = ("solution", "remediation", "recommendation", "fix")
ASSET_TYPE_FIELDS = ("asset_type", "resource_type")
ASSET_NAME_FIELDS = ("asset_name", "resource_name", "asset", "resource")
CVE_FIELDS = ("cve", "cve_id", "cve_ids")
COMPONENT_FIELDS = ("package_name", "component_name", "package", "component")
VERSION_FIELDS = ("package_version", "component_version", "installed_version", "version")
LAST_SEEN_FIELDS = ("last_seen", "present_on_date")
DISCOVERED_FIELDS = ("date_discovered", "first_seen", "created_at")
IGNORED_FIELDS = ("ignored",)

# Some AccuKnox rows prefix the vulnerability columns, so every candidate is tried both bare and
# prefixed.
NESTED_PREFIX = "vulnerability__"

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

DATE_FORMATS = ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d")


class AccuKnoxParser:

    """
    Parses an AccuKnox findings export.

    Mirrors pkg/tools/accuknox/converter field for field so a file import and an API sync deduplicate
    against each other instead of producing two copies of everything.

    AccuKnox returns heterogeneous rows - container scans, IaC, cloud posture, runtime - through one
    endpoint, and the column names differ by data type. The connector therefore probes a list of
    candidate keys per field instead of assuming one schema, and this parser does the same. See the
    *_FIELDS tuples.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanType().
        return ["AccuKnox - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "AccuKnox - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import an AccuKnox findings export (JSON). Matches the scan type used by the AccuKnox "
            "connector so file and API findings deduplicate. Handles AccuKnox's varying column names "
            "across its container, IaC, cloud-posture and runtime data types."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the AccuKnox Parser.

        Mirrors the connector's RowToFinding:
        - title: the row's name, falling back to "AccuKnox finding <id>".
        - severity: the row's risk factor; anything unrecognised Info.
        - description: the prose, then the finding class, status, asset and first/last seen dates.
        - mitigation: the row's solution or remediation text.
        - component_name / component_version: the affected package.
        - service: the asset the finding is on.
        - active / is_mitigated / risk_accepted / duplicate / verified / out_of_scope: from the row's
          status and its ignored flag; see apply_status().
        - unique_id_from_tool: AccuKnox's finding id.
        - vuln_id_from_tool: the data type, which is AccuKnox's finding class.
        """
        return [
            "title",
            "severity",
            "date",
            "description",
            "mitigation",
            "component_name",
            "component_version",
            "service",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "tags",
            "active",
            "is_mitigated",
            "risk_accepted",
            "duplicate",
            "verified",
            "out_of_scope",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the AccuKnox Parser.

        Copied from the AccuKnox block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields.
        """
        return ["title", "severity", "description"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        rows = self.extract_rows(data)

        findings = []
        for row in rows:
            if isinstance(row, dict):
                findings.append(self.build_finding(row, test))
        return findings

    def extract_rows(self, data):
        """AccuKnox's findings endpoint pages rows under "results"; a bare array is common too."""
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("results", "findings", "data", "rows"):
                if isinstance(data.get(key), list):
                    return data[key]
        msg = (
            "An AccuKnox export is a JSON array of finding rows, or an object with a 'results' "
            f"list; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def value(self, row, candidates):
        """
        Return the first non-empty value among the candidate keys.

        Each candidate is tried bare and with AccuKnox's "vulnerability__" column prefix, because
        some data types nest the vulnerability columns that way.
        """
        for candidate in candidates:
            for name in (candidate, NESTED_PREFIX + candidate):
                if name not in row:
                    continue
                rendered = self.scalar(row[name])
                if rendered:
                    return rendered
        return ""

    def scalar(self, value):
        """Render a scalar as text; a list is joined so a cve_ids array is still searchable."""
        if value is None or isinstance(value, (dict,)):
            return ""
        if isinstance(value, bool):
            return str(value).lower()
        if isinstance(value, list):
            return ", ".join(str(v).strip() for v in value if str(v).strip())
        return str(value).strip()

    def flag(self, row, candidates):
        """Read a boolean-ish value, tolerating the string forms AccuKnox uses."""
        for candidate in candidates:
            for name in (candidate, NESTED_PREFIX + candidate):
                if name not in row:
                    continue
                value = row[name]
                if isinstance(value, bool):
                    return value
                if isinstance(value, str):
                    return value.strip().lower() in {"true", "yes", "1"}
                if isinstance(value, (int, float)):
                    return bool(value)
        return False

    def build_finding(self, row, test):
        status = self.value(row, STATUS_FIELDS).lower()

        finding = Finding(
            test=test,
            title=self.title(row),
            severity=self.severity(row),
            date=self.date(row),
            description=self.describe(row),
            mitigation=self.value(row, SOLUTION_FIELDS) or None,
            component_name=self.value(row, COMPONENT_FIELDS) or None,
            component_version=self.value(row, VERSION_FIELDS) or None,
            service=self.value(row, ASSET_NAME_FIELDS) or None,
            unique_id_from_tool=self.value(row, ID_FIELDS) or None,
            # AccuKnox's data_type is its finding class, e.g. container or iac.
            vuln_id_from_tool=self.value(row, DATA_TYPE_FIELDS) or None,
            # AccuKnox reports on stored artefacts and configuration, not a live probe.
            static_finding=True,
            dynamic_finding=False,
        )
        self.apply_status(finding, status)
        finding.unsaved_tags = self.tags(row)

        if self.flag(row, IGNORED_FIELDS):
            # AccuKnox lets a user suppress a row; the connector records that rather than dropping it.
            finding.out_of_scope = True

        cves = self.cves(row)
        if cves:
            finding.unsaved_vulnerability_ids = cves
        return finding

    def apply_status(self, finding, status):
        """
        Translate AccuKnox's status.

        Only fixed, accepted-risk and duplicate close a finding; the working states (active, in
        progress, waiting for 3rd party, exception requested, waiting for verification) stay open.
        A row with NO status is treated as verified, and only "potential" is explicitly unverified.
        """
        finding.is_mitigated = status == STATUS_FIXED
        finding.risk_accepted = status == STATUS_ACCEPTED_RISK
        finding.duplicate = status == STATUS_DUPLICATE
        finding.active = not (finding.is_mitigated or finding.risk_accepted or finding.duplicate)
        finding.verified = status != "" and status != STATUS_POTENTIAL

    def title(self, row):
        """
        The row's name, or the finding id, or a bare constant.

        AccuKnox does not publish the schema for every data type, so a row can arrive with no
        recognisable title at all and still has to import.
        """
        title = self.value(row, TITLE_FIELDS)
        if title:
            return title
        identifier = self.value(row, ID_FIELDS)
        if identifier:
            return f"AccuKnox finding {identifier}"
        return "AccuKnox finding"

    def severity(self, row):
        raw = self.value(row, SEVERITY_FIELDS).lower()
        return SEVERITY_BY_RISK_FACTOR.get(raw, DEFAULT_SEVERITY)

    def describe(self, row):
        sections = []
        prose = self.value(row, DESCRIPTION_FIELDS)
        if prose:
            sections.append(prose)

        details = [
            f"**{label}:** {value}" for label, value in (
                ("Finding class", self.value(row, DATA_TYPE_FIELDS)),
                ("AccuKnox status", self.value(row, STATUS_FIELDS)),
                ("Asset", self.value(row, ASSET_NAME_FIELDS)),
                ("Asset type", self.value(row, ASSET_TYPE_FIELDS)),
                ("First seen", self.value(row, DISCOVERED_FIELDS)),
                ("Last seen", self.value(row, LAST_SEEN_FIELDS)),
            ) if value
        ]
        if details:
            sections.append("\n".join(details))
        return "\n\n".join(sections)

    def tags(self, row):
        return [
            value for value in
            (self.value(row, DATA_TYPE_FIELDS), self.value(row, ASSET_TYPE_FIELDS)) if value
        ]

    def cves(self, row):
        """
        Extract CVEs from the CVE column, falling back to the title.

        AccuKnox often carries the identifier only in the finding name, and the column may hold
        several, so the value is scanned rather than read.
        """
        haystack = self.value(row, CVE_FIELDS) or self.value(row, TITLE_FIELDS)
        found, seen = [], set()
        for cve in CVE_PATTERN.findall(haystack):
            upper = cve.upper()
            if upper not in seen:
                seen.add(upper)
                found.append(upper)
        return found

    def date(self, row):
        """The discovery date, from whichever of AccuKnox's date columns the row carries."""
        raw = self.value(row, DISCOVERED_FIELDS)
        if not raw:
            return None
        with suppress(ValueError):
            return datetime.fromisoformat(raw).date()
        for fmt in DATE_FORMATS:
            with suppress(ValueError):
                return datetime.strptime(raw, fmt).date()
        return None
