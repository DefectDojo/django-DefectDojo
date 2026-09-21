import json
from contextlib import suppress

from dojo.models import Finding

# Mirrors severityFromRating() in the HackerOne connector's converter. HackerOne also reports a
# rating of "none", which falls through to Info like anything else unrecognised.
SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
DEFAULT_SEVERITY = "Info"

REPORT_URL = "https://hackerone.com/reports/{}"


class HackerOneParser:

    """
    Parses a HackerOne reports export.

    Mirrors pkg/tools/hackerone/connector/converter.go field for field so a file import and an API
    sync deduplicate against each other instead of producing two copies of everything.

    HackerOne's API is JSON:API, so severity, weakness and reporter arrive as relationships rather
    than plain attributes. This parser reads that shape, and also accepts an already-flattened export.
    """

    def get_scan_types(self):
        # Byte-identical to ScanTypeName in the connector.
        return ["HackerOne - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "HackerOne - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a HackerOne reports export (JSON:API). Matches the scan type used by the "
            "HackerOne connector so file and API findings deduplicate. One finding per report."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the HackerOne Parser.

        Mirrors the connector's toFinding:
        - title: the report title.
        - severity: the severity relationship's rating; anything unrecognised Info.
        - description: the vulnerability information, the weakness name, the reporting researcher,
          and a link to the report.
        - url: the report's public URL.
        - cwe: parsed from the weakness relationship's external_id, e.g. "cwe-79".
        - cvssv3_score: the severity relationship's score, when it is above zero.
        - unique_id_from_tool / vuln_id_from_tool: both the HackerOne report id.
        """
        return [
            "title",
            "severity",
            "description",
            "url",
            "cwe",
            "cvssv3_score",
            "unique_id_from_tool",
            "vuln_id_from_tool",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the HackerOne Parser.

        Copied from the HackerOne block in the Pro connector settings: report ids are globally unique
        on the platform, so the plain hash_code algorithm hashes the unique id alone. Diverging would
        stop file findings merging with API-synced ones.
        """
        return ["unique_id_from_tool"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        reports = self.extract_reports(data)

        findings = {}
        for report in reports:
            if not isinstance(report, dict):
                continue
            finding = self.build_finding(report, test)
            findings.setdefault(finding.unique_id_from_tool, finding)
        return list(findings.values())

    def extract_reports(self, data):
        """HackerOne's JSON:API responses put the reports under "data"."""
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("data", "reports"):
                if isinstance(data.get(key), list):
                    return data[key]
        msg = (
            "A HackerOne export is a JSON:API object with a 'data' list of reports, or a bare array "
            f"of reports; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def build_finding(self, report, test):
        attributes = report.get("attributes") or {}
        severity = self.relationship(report, "severity")
        weakness = self.relationship(report, "weakness")
        reporter = self.relationship(report, "reporter")

        report_id = str(report.get("id") or "")
        score = severity.get("score") or 0

        finding = Finding(
            test=test,
            title=attributes.get("title") or report.get("title") or None,
            severity=SEVERITY_MAP.get(
                (severity.get("rating") or "").strip().lower(), DEFAULT_SEVERITY,
            ),
            description=self.describe(report, attributes, weakness, reporter, report_id),
            url=REPORT_URL.format(report_id),
            cwe=self.cwe(weakness.get("external_id")),
            unique_id_from_tool=report_id,
            vuln_id_from_tool=report_id or None,
        )
        # The converter only sets a score when HackerOne actually attached one.
        if score > 0:
            finding.cvssv3_score = score
        return finding

    def relationship(self, report, name):
        """
        Read one JSON:API relationship's attributes.

        Severity, weakness and reporter are relationships on a HackerOne report, not attributes, so
        each is nested under relationships.<name>.data.attributes. An already-flattened export is
        also accepted, which is why the top-level object is checked as a fallback.
        """
        relationships = report.get("relationships")
        if isinstance(relationships, dict):
            entry = relationships.get(name)
            if isinstance(entry, dict):
                inner = entry.get("data")
                if isinstance(inner, dict):
                    attributes = inner.get("attributes")
                    if isinstance(attributes, dict):
                        return attributes
        # Flattened form: the fields sit on the report itself.
        flat = report.get(name)
        return flat if isinstance(flat, dict) else {}

    def describe(self, report, attributes, weakness, reporter, report_id):
        parts = []
        information = attributes.get("vulnerability_information") or report.get(
            "vulnerability_information",
        )
        if information:
            parts.append(information)
        if weakness.get("name"):
            parts.append(f"**Weakness:** {weakness['name']}")
        if reporter.get("username"):
            parts.append(f"**Reported by:** {reporter['username']}")
        # The converter always appends the report link, even with nothing else to say.
        parts.append(f"**Report:** {REPORT_URL.format(report_id)}")
        return "\n\n".join(parts)

    def cwe(self, external_id):
        """The weakness external_id is lower-cased, e.g. "cwe-79"; anything else leaves 0."""
        raw = str(external_id or "").strip().lower()
        if not raw.startswith("cwe-"):
            return 0
        with suppress(ValueError):
            number = int(raw[4:])
            if number > 0:
                return number
        return 0
