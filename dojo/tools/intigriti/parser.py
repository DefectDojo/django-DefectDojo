import json
from contextlib import suppress
from html.parser import HTMLParser

from dojo.models import Finding

# Mirrors severityFromValue() in the Intigriti connector's converter. Intigriti grades its top tier
# "exceptional" rather than "critical", and both are accepted.
SEVERITY_MAP = {
    "exceptional": "Critical",
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
DEFAULT_SEVERITY = "Info"

# Close reasons that mean the submission was accepted as a risk rather than fixed.
RISK_ACCEPTED_REASONS = frozenset({"accepted risk", "risk accepted", "accepted-risk"})
OUT_OF_SCOPE_REASONS = frozenset({"out of scope", "out-of-scope", "outofscope"})
# Close reasons that mean the submission was not a real issue. Intigriti's "no" is its terse
# rejection reason.
FALSE_POSITIVE_REASONS = frozenset({
    "not applicable", "not-applicable", "not reproducible", "not-reproducible",
    "false positive", "spam", "informative", "won't fix", "wont fix", "no",
})

# Block-level tags the connector's HTML flattener turns into newlines, and the tags whose content is
# dropped. The connectors repo duplicates this sanitizer per tool rather than sharing it, so it is
# reproduced here rather than imported from another parser.
BLOCK_TAGS = frozenset({
    "br", "p", "div", "li", "tr", "ul", "ol", "table", "blockquote",
    "h1", "h2", "h3", "h4", "h5", "h6",
})
DROPPED_TAGS = frozenset({"script", "style"})

# Go's html.EscapeString, applied last. Python's html.escape differs on the apostrophe, so the
# replacements are spelled out to match byte for byte.
GO_HTML_ESCAPES = (
    ("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"), ('"', "&#34;"), ("'", "&#39;"),
)


class _HtmlFlattener(HTMLParser):

    """Mirror of the connector's htmlFlattener: drop script/style, block tags become newlines."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in DROPPED_TAGS:
            self.skip_depth += 1
        elif tag in BLOCK_TAGS:
            self.parts.append("\n")

    def handle_startendtag(self, tag, attrs):
        if tag in BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in DROPPED_TAGS:
            self.skip_depth = max(0, self.skip_depth - 1)
        elif tag in BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data):
        if self.skip_depth == 0:
            self.parts.append(data)

    def text(self):
        return "".join(self.parts)


def inert_text(raw_html):
    """
    Flatten researcher-submitted HTML to escaped plain text, as the connector's InertText does.

    Intigriti submissions are written by external researchers, so their prose is never passed through
    as markup.
    """
    if not raw_html:
        return ""
    flattener = _HtmlFlattener()
    flattener.feed(raw_html)
    flattener.close()
    return go_escape(collapse_whitespace(flattener.text()))


def collapse_whitespace(text):
    """Trim every line, collapse runs of blank lines to one, and drop trailing blanks."""
    out, blank = [], True
    for raw in text.split("\n"):
        line = raw.strip()
        if not line:
            if not blank:
                out.append("")
            blank = True
            continue
        out.append(line)
        blank = False
    while out and not out[-1]:
        out.pop()
    return "\n".join(out)


def go_escape(text):
    for character, entity in GO_HTML_ESCAPES:
        text = text.replace(character, entity)
    return text


class IntigritiParser:

    """
    Parses an Intigriti submissions export.

    Mirrors pkg/tools/intigriti/connector/converter.go field for field so a file import and an API
    sync deduplicate against each other instead of producing two copies of everything.

    The connector converts each submission from TWO objects - a list overview and a fetched detail -
    preferring the overview for any field both carry. An export may hold either or both; see split().
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanType().
        return ["Intigriti - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Intigriti - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import an Intigriti submissions export (JSON). Matches the scan type used by the "
            "Intigriti connector so file and API findings deduplicate. The submission's status and "
            "close reason are translated into the corresponding DefectDojo state."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Intigriti Parser.

        Mirrors the connector's Convert:
        - title: the overview title, falling back to the detail's.
        - severity: the severity value; Intigriti's top tier is "exceptional".
        - description: report type, asset, proof of concept, the researcher's question answers, and
          the submission code.
        - impact / mitigation: the report's impact and recommended solution, flattened to text.
        - url / references: the Intigriti portal link for the submission.
        - cvssv3: the severity vector.
        - cwe: from the report type's cwe, e.g. "cwe-79".
        - unique_id_from_tool / vuln_id_from_tool: both the submission code.
        - active / verified / is_mitigated / risk_accepted / false_p / duplicate / out_of_scope: from
          the status and close reason; see apply_state().
        """
        return [
            "title",
            "severity",
            "description",
            "impact",
            "mitigation",
            "url",
            "references",
            "cvssv3",
            "cwe",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "active",
            "verified",
            "is_mitigated",
            "risk_accepted",
            "false_p",
            "duplicate",
            "out_of_scope",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Intigriti Parser.

        Copied from the Intigriti block in the Pro connector settings: submission codes are globally
        unique on the platform, so the plain hash_code algorithm hashes the unique id alone.
        """
        return ["unique_id_from_tool"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        entries = self.extract_entries(data)

        findings = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            finding = self.build_finding(entry, test)
            findings.setdefault(finding.unique_id_from_tool, finding)
        return list(findings.values())

    def extract_entries(self, data):
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("records", "submissions", "data", "items"):
                if isinstance(data.get(key), list):
                    return data[key]
        msg = (
            "An Intigriti export is a JSON object with a 'records' list of submissions, or a bare "
            f"array of submissions; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def split(self, entry):
        """
        Separate the overview from the detail.

        The connector holds them apart because it lists submissions and then fetches each one. An
        export may nest the detail under "detail", or - if it was taken from the detail endpoint -
        carry the report on the entry itself, which is what the "report" check picks up.
        """
        detail = entry.get("detail") if isinstance(entry.get("detail"), dict) else None
        if detail is None and isinstance(entry.get("report"), dict):
            detail = entry
        return entry, detail

    def build_finding(self, entry, test):
        overview, detail = self.split(entry)
        code = overview.get("code") or (detail or {}).get("code") or ""

        severity_value = self.first(
            self.nested(overview, "severity", "value"),
            self.nested(detail, "severity", "value"),
        )
        vector = self.first(
            self.nested(overview, "severity", "vector"),
            self.nested(detail, "severity", "vector"),
        )
        portal_url = self.first(
            self.nested(overview, "webLinks", "details"),
            self.nested(detail, "webLinks", "details"),
        )

        finding = Finding(
            test=test,
            title=self.first(overview.get("title"), (detail or {}).get("title")) or None,
            severity=SEVERITY_MAP.get(severity_value.strip().lower(), DEFAULT_SEVERITY),
            description=self.describe(overview, detail, code),
            unique_id_from_tool=code,
            vuln_id_from_tool=code or None,
            # A bug-bounty submission is a researcher testing a running target.
            static_finding=False,
            dynamic_finding=True,
        )

        if portal_url:
            finding.url = portal_url
            finding.references = f"Intigriti submission: {portal_url}"
        if vector:
            finding.cvssv3 = vector

        if detail:
            report = detail.get("report") if isinstance(detail.get("report"), dict) else {}
            cwe = self.cwe(self.nested(report, "type", "cwe"))
            if cwe:
                finding.cwe = cwe
            if impact := inert_text(report.get("impact")):
                finding.impact = impact
            if solution := inert_text(report.get("recommendedSolution")):
                finding.mitigation = solution

        self.apply_state(finding, *self.state(overview, detail))
        return finding

    def state(self, overview, detail):
        """The overview's status and close reason, each falling back to the detail's."""
        status = self.first(
            self.nested(overview, "state", "status", "value"),
            self.nested(detail, "state", "status", "value"),
        )
        close_reason = self.first(
            self.nested(overview, "state", "closeReason", "value"),
            self.nested(detail, "state", "closeReason", "value"),
        )
        return status, close_reason

    def apply_state(self, finding, status, close_reason):
        """
        Translate Intigriti's status, and for a closed submission its close reason, into state.

        Importing everything as active would put closed submissions back in front of the team, and
        the close reason is what distinguishes a fix from a rejection or an accepted risk.
        """
        normalised = self.normalise(status)
        if normalised in {"closed", "archived"}:
            self.apply_closed_state(finding, self.normalise(close_reason))
            return
        finding.active = True
        finding.verified = normalised == "accepted"

    def apply_closed_state(self, finding, reason):
        finding.active = False
        if reason in RISK_ACCEPTED_REASONS:
            finding.verified = True
            finding.risk_accepted = True
        elif reason == "duplicate":
            finding.duplicate = True
        elif reason in OUT_OF_SCOPE_REASONS:
            finding.out_of_scope = True
        elif reason in FALSE_POSITIVE_REASONS:
            finding.false_p = True
        else:
            # Solved, resolved, fixed, or closed with no specific reason.
            finding.verified = True
            finding.is_mitigated = True

    def describe(self, overview, detail, code):
        parts = []
        if detail:
            report = detail.get("report") if isinstance(detail.get("report"), dict) else {}
            if label := self.report_type_label(report.get("type")):
                parts.append(f"**Type:** {label}")
            if asset := self.report_asset(report):
                parts.append(f"**Asset:** {inert_text(asset)}")
            if poc := inert_text(report.get("pocDescription")):
                parts.append(f"**Proof of concept:**\n{poc}")
            questions = report.get("questions")
            if isinstance(questions, list):
                for question in questions:
                    if not isinstance(question, dict):
                        continue
                    if not (question.get("question") or question.get("answer")):
                        continue
                    heading = inert_text(question.get("question"))
                    parts.append(f"**{heading}**\n{inert_text(question.get('answer'))}")
        # The converter always appends the submission code.
        parts.append(f"**Submission:** {code}")
        return "\n\n".join(parts)

    def report_type_label(self, report_type):
        """"<name> (<category>)", degrading to whichever of the two Intigriti supplied."""
        if not isinstance(report_type, dict):
            return ""
        name = inert_text(report_type.get("name"))
        category = inert_text(report_type.get("category"))
        if name and category:
            return f"{name} ({category})"
        return name or category

    def report_asset(self, report):
        """The affected domain, falling back to the vulnerable component Intigriti recorded."""
        domain = report.get("domain")
        if isinstance(domain, dict) and domain.get("name"):
            return domain["name"]
        return report.get("endpointVulnerableComponent") or ""

    def cwe(self, raw):
        """Intigriti writes this lower-cased as "cwe-<n>"; anything else leaves 0."""
        trimmed = str(raw or "").strip().lower()
        if not trimmed.startswith("cwe-"):
            return 0
        with suppress(ValueError):
            number = int(trimmed[4:])
            if number > 0:
                return number
        return 0

    def nested(self, source, *keys):
        """Walk nested dicts, returning "" as soon as anything is missing or the wrong type."""
        current = source
        for key in keys:
            if not isinstance(current, dict):
                return ""
            current = current.get(key)
        return current if isinstance(current, str) else ""

    def first(self, *values):
        for value in values:
            if value:
                return value
        return ""

    def normalise(self, value):
        return (value or "").strip().lower()
