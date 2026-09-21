import json
from contextlib import suppress
from datetime import date as _date

from dojo.models import Finding

SEVERITY_BY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
# BigID has no Info tier of its own, so an unknown or missing level lands here.
DEFAULT_SEVERITY = "Info"

# Statuses that mean BigID considers the case dealt with.
CLOSED_STATUSES = {"resolved", "remediated", "closed"}

# BigID's case fields are camelCase, but the two timestamps are snake_case.
DATE_KEYS = ("updated_at", "created_at")


class BigidParser:

    """
    Parses a BigID DSPM case export.

    Mirrors pkg/tools/bigid/connector/finding_converter field for field so a file import and an API
    sync deduplicate against each other instead of producing two copies of everything.

    PRIVACY: a BigID case is about sensitive data that was found, so only the case identity, its
    policy and data-source context and the COUNT of affected objects are read. No sample, preview or
    value of the data itself is read out of the export or written into a finding, even if the file
    contains one - see describe().
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName. Note it does NOT follow the
        # "<Vendor> - Connectors Import" pattern, so it cannot be derived - it has to be copied.
        return ["BigID Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "BigID Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a BigID DSPM case export (JSON). Only the policy and data-source context and the "
            "count of affected objects are read - never a sample of the data itself. Matches the scan "
            "type used by the BigID connector so file and API findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the BigID Parser.

        Mirrors the connector's Convert:
        - title: the case label, then the policy name, then the case id.
        - severity: BigID's severityLevel; anything unrecognised is Info.
        - description: the policy, data source, sensitivity, affected-object COUNT, status, assignee.
        - mitigation: BigID's own remediation steps.
        - component_name: the data source the case is about.
        - active / is_mitigated: from the case status; see is_open().
        - unique_id_from_tool: "bigid-<case id>".
        """
        return [
            "title",
            "severity",
            "description",
            "mitigation",
            "component_name",
            "date",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "tags",
            "active",
            "is_mitigated",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the BigID Parser.

        Copied from the BigID block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. The data source is the component, so
        the same policy failing on two data sources stays two findings.
        """
        return ["title", "severity", "component_name"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        findings = []
        for row in self.cases(data):
            case_id = str(row.get("caseId") or "").strip()
            if not case_id:
                # The case id is the whole identity; without one every row would collapse onto
                # "bigid-".
                continue
            findings.append(self.build_finding(row, case_id, test))
        return findings

    def cases(self, data):
        """
        Return the cases in the export.

        BigID's own samples disagree about the shape, so its client accepts all three: a bare array,
        a {"data": {"cases": [...]}} object, and a top-level {"cases": [...]}. The wrapped form wins
        when it carries anything, which is the precedence the client applies.
        """
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]

        if isinstance(data, dict):
            wrapped = data.get("data")
            if isinstance(wrapped, dict) and (
                isinstance(wrapped.get("cases"), list) or self.flex_int(wrapped.get("totalCount")) > 0
            ):
                return [row for row in wrapped.get("cases") or [] if isinstance(row, dict)]
            if isinstance(data.get("cases"), list):
                return [row for row in data["cases"] if isinstance(row, dict)]

        msg = (
            "A BigID export is the cases response - a JSON array of cases, or an object with a "
            f"'cases' list; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def build_finding(self, row, case_id, test):
        open_case = self.is_open(row)

        finding = Finding(
            test=test,
            title=self.title(row, case_id),
            severity=self.severity(row),
            description=self.describe(row),
            mitigation=str(row.get("remediationSteps") or "") or None,
            component_name=str(row.get("dataSourceName") or "") or None,
            unique_id_from_tool=f"bigid-{case_id}",
            vuln_id_from_tool=case_id,
            # BigID inspects data at rest; nothing is exercised.
            static_finding=True,
            dynamic_finding=False,
            active=open_case,
            is_mitigated=not open_case,
        )
        finding.unsaved_tags = self.tags(row)

        if date := self.date(row):
            finding.date = date
        return finding

    def title(self, row, case_id):
        for key in ("caseLabel", "policyName"):
            if value := str(row.get(key) or "").strip():
                return value
        return f"BigID case {case_id}"

    def severity(self, row):
        label = str(row.get("severityLevel") or "").strip().lower()
        return SEVERITY_BY_LABEL.get(label, DEFAULT_SEVERITY)

    def describe(self, row):
        """
        The policy that failed, the data source it failed on, and how much is affected.

        Only the COUNT of affected objects is reported. A BigID case is about sensitive data, so no
        sample or preview of it is read out of the export, whatever the file happens to carry.
        """
        lines = []
        fields = (
            ("Policy", "policyName"),
            ("Policy description", "policyDescription"),
            ("Data source", "dataSourceName"),
            ("Data source type", "dataSourceType"),
            ("Sensitivity", "sensitivityGroup"),
        )
        for label, key in fields:
            if value := str(row.get(key) or "").strip():
                lines.append(f"**{label}:** {value}")

        if (count := self.flex_int(row.get("numberOfAffectedObjects"))) > 0:
            lines.append(f"**Affected objects:** {count}")

        for label, key in (("Status", "caseStatus"), ("Assignee", "assignee")):
            if value := str(row.get(key) or "").strip():
                lines.append(f"**{label}:** {value}")
        return "\n".join(lines).strip()

    def is_open(self, row):
        """A case stays active until BigID reports it resolved, remediated or closed."""
        return str(row.get("caseStatus") or "").strip().lower() not in CLOSED_STATUSES

    def tags(self, row):
        """The data-source type and sensitivity classification, for filtering."""
        return [
            value
            for value in (str(row.get(key) or "").strip() for key in ("dataSourceType", "sensitivityGroup"))
            if value
        ]

    def date(self, row):
        """
        The date part of the update timestamp, falling back to creation.

        The connector takes the first ten characters rather than parsing, because it hands the API a
        string. This has to produce a real date for the model field, so the same ten characters are
        read as an ISO date; one that is not a date is skipped rather than failing the import.
        """
        for key in DATE_KEYS:
            value = str(row.get(key) or "").strip()
            if len(value) >= 10:
                with suppress(ValueError):
                    return _date.fromisoformat(value[:10])
        return None

    def flex_int(self, value):
        """BigID may send a count as a JSON number or a quoted string."""
        if isinstance(value, bool) or value is None:
            return 0
        if isinstance(value, int | float):
            return int(value)
        if isinstance(value, str):
            with suppress(ValueError):
                return int(float(value.strip() or 0))
        return 0
