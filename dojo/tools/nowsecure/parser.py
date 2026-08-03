import json
import re
from contextlib import suppress
from datetime import datetime

from dojo.models import Finding

SEVERITY_BY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "informational": "Info",
    "": "Info",
}
DEFAULT_SEVERITY = "Info"

ANALYSIS_STATIC = "static"
ANALYSIS_DYNAMIC = "dynamic"

# The advisory identifiers the connector's shared extractor recognises in free text.
VULNERABILITY_ID_PATTERN = re.compile(
    r"CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|GO-\d{4}-\d+|RHSA-\d{4}:\d+",
)


class NowSecureParser:

    """
    Parses a NowSecure assessment export.

    Mirrors pkg/tools/nowsecure/connector/finding_converter field for field so a file import and an API
    sync deduplicate against each other instead of producing two copies of everything.

    A NowSecure assessment runs both a static and a dynamic analysis of the same mobile app, and each
    finding says which one found it - so static-versus-dynamic is decided per finding, not per file.
    The assessment also supplies the date and the platform, so an export should carry it; see extract().
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName - just "NowSecure", which does NOT follow the
        # "<Vendor> - Connectors Import" pattern, so it cannot be derived.
        return ["NowSecure"]

    def get_label_for_scan_types(self, scan_type):
        return "NowSecure"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a NowSecure assessment export (JSON), the findings of one mobile-app assessment. "
            "Matches the scan type used by the NowSecure connector so file and API findings "
            "deduplicate. Only findings NowSecure marks as affecting the app are imported."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the NowSecure Parser.

        Mirrors the connector's Convert:
        - title: the finding title, then "NowSecure: <check id>", then a constant.
        - severity: NowSecure's own label; anything unrecognised is Info.
        - description: the category, check and analysis type, then the description and detail.
        - mitigation: the developer recommendation.
        - cvssv3 / cvssv3_score: NowSecure's vector and score.
        - date: when the assessment was created.
        - static_finding / dynamic_finding: from the finding's own analysis type.
        - unique_id_from_tool: "nowsecure-<check id>[-<vulnerability id>]".
        """
        return [
            "title",
            "severity",
            "date",
            "description",
            "mitigation",
            "cvssv3",
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
        Return the list of fields used for deduplication in the NowSecure Parser.

        Copied from the NowSecure block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields.
        """
        return ["title", "severity", "component_name"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        rows, assessment = self.extract(data)

        findings = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            if not row.get("affected") or row.get("hidden"):
                # NowSecure reports every check it ran. Only one that actually affects the app is a
                # finding, and a hidden one has been suppressed in NowSecure itself.
                continue
            findings.append(self.build_finding(row, assessment, test))
        return findings

    def extract(self, data):
        """
        Return the findings and the assessment they belong to.

        NowSecure's findings endpoint answers with a bare array, so an export is either that array or
        an object carrying it alongside the assessment - which is where the date and platform live.
        """
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)], {}
        if isinstance(data, dict):
            for key in ("findings", "results"):
                if isinstance(data.get(key), list):
                    rows = [row for row in data[key] if isinstance(row, dict)]
                    assessment = data.get("assessment")
                    return rows, assessment if isinstance(assessment, dict) else {}

        msg = (
            "A NowSecure export is an assessment's findings, a JSON array or an object with a "
            f"'findings' list; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def build_finding(self, row, assessment, test):
        finding = Finding(
            test=test,
            title=self.title(row),
            severity=self.severity(row),
            description=self.describe(row),
            mitigation=self.mitigation(row),
            unique_id_from_tool=self.unique_id(row),
            vuln_id_from_tool=str(row.get("check_id") or "") or None,
            # NowSecure reports what it found in this assessment, so every finding is current.
            active=True,
        )
        # Set unconditionally, as the connector does.
        finding.cvssv3_score = self.score(row)
        finding.cvssv3 = str(row.get("cvss_vector") or "") or None
        finding.unsaved_tags = self.tags(row, assessment)

        if identifiers := self.vulnerability_ids(row):
            finding.unsaved_vulnerability_ids = identifiers
        if date := self.date(assessment):
            finding.date = date
        self.set_analysis_type(finding, row)
        return finding

    def unique_id(self, row):
        """
        "nowsecure-<check id>[-<vulnerability id>]".

        The check id is the rule; the vulnerability id distinguishes two hits of the same check in one
        app. A finding with no check id falls back to a slug of its title, because something stable is
        needed and the title is all there is.
        """
        base = str(row.get("check_id") or "")
        if not base:
            base = str(row.get("title") or "").lower().replace(" ", "-")
        identifier = row.get("unique_vulnerability_id")
        if isinstance(identifier, int | float) and not isinstance(identifier, bool) and identifier != 0:
            base += f"-{int(identifier)}"
        return f"nowsecure-{base}"

    def title(self, row):
        if title := str(row.get("title") or ""):
            return title
        if check := str(row.get("check_id") or ""):
            return f"NowSecure: {check}"
        return "NowSecure finding"

    def severity(self, row):
        label = str(row.get("severity") or "").strip().lower()
        return SEVERITY_BY_LABEL.get(label, DEFAULT_SEVERITY)

    def score(self, row):
        value = row.get("cvss")
        if isinstance(value, int | float) and not isinstance(value, bool):
            return float(value)
        return 0.0

    def describe(self, row):
        """
        The category, check and analysis type as single-newline bullets, then the prose sections.

        The prose is separated by a blank line because it is paragraphs rather than fields - that is
        the connector's own distinction, mirrored here.
        """
        lines = []
        for label, key in (("Category", "category"), ("Check", "check_id"), ("Analysis", "analysis_type")):
            value = str(row.get(key) or "")
            if value:
                lines.append(f"**{label}:** {value}")
        text = "\n".join(lines)

        for label, key in (("Description", "description"), ("Detail", "vulnerability_detail")):
            value = str(row.get(key) or "")
            if not value:
                continue
            if text:
                text += "\n\n"
            text += f"**{label}:**\n{value}"
        return text.strip()

    def mitigation(self, row):
        """NowSecure writes its advice for the developer; there is no other recommendation field."""
        recommendations = row.get("recommendations")
        if isinstance(recommendations, dict):
            return str(recommendations.get("developer") or "")
        return ""

    def vulnerability_ids(self, row):
        """
        Identifiers found in the title, description and detail.

        The connector's shared extractor SORTS these and drops case-insensitive duplicates, unlike the
        order-preserving path other connectors use - mirrored so the two import paths agree.
        """
        prose = "|".join([
            str(row.get("title") or ""),
            str(row.get("description") or ""),
            str(row.get("vulnerability_detail") or ""),
        ])
        found = sorted(VULNERABILITY_ID_PATTERN.findall(prose))

        identifiers = []
        for candidate in found:
            if not identifiers or identifiers[-1].lower() != candidate.lower():
                identifiers.append(candidate)
        return identifiers

    def date(self, assessment):
        """The assessment's creation time, which is when the app was analysed."""
        created = str(assessment.get("created") or "").strip()
        if not created:
            return None
        with suppress(ValueError):
            return datetime.strptime(created.split("T")[0], "%Y-%m-%d").date()
        return None

    def tags(self, row, assessment):
        tags = []
        for value in (row.get("category"), row.get("analysis_type"), assessment.get("platform")):
            text = str(value or "")
            if text:
                tags.append(text)
        return tags

    def set_analysis_type(self, finding, row):
        """
        Static or dynamic, per finding.

        One NowSecure assessment runs both analyses of the same app, so the file cannot decide this.
        An analysis type the connector does not recognise leaves both flags at their default rather
        than guessing which kind of test ran.
        """
        analysis = str(row.get("analysis_type") or "").strip().lower()
        if analysis == ANALYSIS_STATIC:
            finding.static_finding = True
            finding.dynamic_finding = False
        elif analysis == ANALYSIS_DYNAMIC:
            finding.static_finding = False
            finding.dynamic_finding = True
