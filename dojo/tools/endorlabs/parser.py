import json
from html.parser import HTMLParser

from dojo.models import Finding

# Endor Labs grades findings with these enum values; the connector clamps anything else to Info.
SEVERITY_MAP = {
    "FINDING_LEVEL_CRITICAL": "Critical",
    "FINDING_LEVEL_HIGH": "High",
    "FINDING_LEVEL_MEDIUM": "Medium",
    "FINDING_LEVEL_LOW": "Low",
}
DEFAULT_SEVERITY = "Info"

# Reachability is Endor's headline signal, so the connector surfaces it as the finding impact rather
# than burying it in tags. The order here is the connector's: a function verdict outranks a
# dependency verdict, and a definite verdict outranks a "potentially".
REACHABILITY_SUMMARY = [
    ("FINDING_TAGS_REACHABLE_FUNCTION", "Reachable (vulnerable function is called)"),
    ("FINDING_TAGS_UNREACHABLE_FUNCTION", "Unreachable (vulnerable function is not called)"),
    ("FINDING_TAGS_POTENTIALLY_REACHABLE_FUNCTION",
     "Potentially reachable (function reachability undetermined)"),
    ("FINDING_TAGS_REACHABLE_DEPENDENCY", "Reachable (dependency is used)"),
    ("FINDING_TAGS_UNREACHABLE_DEPENDENCY", "Unreachable (dependency is not used)"),
    ("FINDING_TAGS_POTENTIALLY_REACHABLE_DEPENDENCY",
     "Potentially reachable (dependency reachability undetermined)"),
]

FINDING_TAG_PREFIX = "FINDING_TAGS_"
FINDING_CATEGORY_PREFIX = "FINDING_CATEGORY_"

# Tags that only say "we did not determine this" carry no information.
UNSPECIFIED_SUFFIX = "_UNSPECIFIED"

# Block-level tags the connector's HTML flattener turns into newlines.
BLOCK_TAGS = frozenset({
    "br", "p", "div", "li", "tr", "ul", "ol", "table", "blockquote",
    "h1", "h2", "h3", "h4", "h5", "h6",
})
# Tags whose text content is dropped entirely.
DROPPED_TAGS = frozenset({"script", "style"})

# Go's html.EscapeString, which the connector applies last. Python's html.escape differs on the
# apostrophe (&#x27; rather than &#39;), so the replacement is spelled out to match byte for byte.
GO_HTML_ESCAPES = (
    ("&", "&amp;"),
    ("<", "&lt;"),
    (">", "&gt;"),
    ('"', "&#34;"),
    ("'", "&#39;"),
)


class _HtmlFlattener(HTMLParser):

    """
    Mirror of the connector's htmlFlattener.

    Endor Labs advisory text arrives as HTML, and the connector flattens it rather than rendering it:
    script and style content is dropped, block tags become newlines, and everything else becomes
    plain text.
    """

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
        # A self-closing script or style has no content to skip, so only the newline case applies.
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
    Flatten HTML to escaped plain text, as the connector's InertText does.

    Advisory text from Endor Labs is attacker-influenced in the sense that it comes from upstream
    advisories, so it is never passed through as markup.
    """
    if not raw_html:
        return ""
    flattener = _HtmlFlattener()
    flattener.feed(raw_html)
    flattener.close()
    return go_escape(collapse_whitespace(flattener.text()))


def collapse_whitespace(text):
    """Trim every line, collapse runs of blank lines to one, and drop trailing blanks."""
    out = []
    blank = True
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


class EndorLabsParser:

    """
    Parses an Endor Labs findings export.

    Mirrors pkg/tools/endorlabs/connector/converter.go field for field so a file import and an API
    sync deduplicate against each other instead of producing two copies of everything.

    Endor Labs is reachability-aware SCA: its distinguishing output is whether the vulnerable code is
    actually called. That verdict is set as the finding's impact, which is where the connector puts
    it.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanType().
        return ["Endor Labs - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Endor Labs - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import an Endor Labs findings export (JSON). Matches the scan type used by the Endor "
            "Labs connector so file and API findings deduplicate. Endor's reachability verdict is "
            "imported as the finding's impact."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Endor Labs Parser.

        Mirrors the connector's FindingConverter.Convert:
        - title: Endor's own finding name, falling back to "<vuln id> in <component>:<version>".
        - severity: the finding level enum, anything unrecognised Info.
        - description: summary, explanation, reachability, vulnerability summary, EPSS, references.
        - impact: the reachability verdict.
        - mitigation: Endor's remediation advice.
        - cvssv3 / cvssv3_score: the CVSS v3 vector and score, falling back to the v4 base score.
        - component_name / component_version: the target dependency.
        - unique_id_from_tool: the Endor finding UUID, which is stable across syncs.
        - vuln_id_from_tool: the primary vulnerability identifier.
        """
        return [
            "title",
            "severity",
            "description",
            "impact",
            "mitigation",
            "cvssv3",
            "cvssv3_score",
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
        Return the list of fields used for deduplication in the Endor Labs Parser.

        Copied from the Endor Labs block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. Diverging would stop file findings
        merging with API-synced ones.
        """
        return ["title", "severity", "vuln_id_from_tool"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        rows = self.extract_rows(data)

        findings = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            finding = self.build_finding(row, test)
            findings.setdefault(finding.unique_id_from_tool, finding)
        return list(findings.values())

    def extract_rows(self, data):
        """Endor's list endpoints nest the results under "list"."objects"."""
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            listing = data.get("list")
            if isinstance(listing, dict) and isinstance(listing.get("objects"), list):
                return listing["objects"]
            if isinstance(data.get("objects"), list):
                return data["objects"]
        msg = (
            "An Endor Labs export is a JSON object with a 'list' containing 'objects', or a bare "
            f"array of findings; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def build_finding(self, row, test):
        spec = row.get("spec") or {}
        vulnerability = self.vulnerability(row)
        name, version = self.component(spec)
        tags = spec.get("finding_tags") or []
        reachability = self.reachability_summary(tags)

        finding = Finding(
            test=test,
            title=self.title(row, spec, name, version),
            severity=SEVERITY_MAP.get((spec.get("level") or "").strip().upper(), DEFAULT_SEVERITY),
            description=self.describe(spec, vulnerability, reachability),
            component_name=name or None,
            component_version=version or None,
            unique_id_from_tool=self.unique_id(row, spec, name, version),
            vuln_id_from_tool=self.primary_vuln_id(vulnerability) or None,
            # Endor Labs reads a dependency graph, never a running service.
            static_finding=True,
            dynamic_finding=False,
        )

        if reachability:
            # The connector promotes reachability to impact so triagers see it prominently.
            finding.impact = reachability
        if remediation := (spec.get("remediation") or "").strip():
            finding.mitigation = inert_text(remediation)
        if score := self.cvss_score(vulnerability):
            finding.cvssv3_score = score
        if vector := self.cvss_v3_vector(vulnerability):
            finding.cvssv3 = vector
        if ids := self.vulnerability_ids(vulnerability):
            finding.unsaved_vulnerability_ids = ids

        finding.unsaved_tags = self.tags(spec)
        return finding

    def vulnerability(self, row):
        metadata = (row.get("spec") or {}).get("finding_metadata") or {}
        vulnerability = metadata.get("vulnerability")
        return vulnerability if isinstance(vulnerability, dict) else None

    def component(self, spec):
        """The dependency name, preferring the resolved name over the package name."""
        name = (spec.get("target_dependency_name") or "").strip()
        if not name:
            name = (spec.get("target_dependency_package_name") or "").strip()
        return name, (spec.get("target_dependency_version") or "").strip()

    def unique_id(self, row, spec, name, version):
        """
        The Endor finding UUID, which is stable across syncs.

        The converter falls back to a vulnerability and component composite when a finding somehow
        arrives without one.
        """
        if uuid := (row.get("uuid") or "").strip():
            return uuid
        return f"{self.primary_vuln_id(self.vulnerability(row))}|{name}:{version}"

    def title(self, row, spec, name, version):
        if title := ((row.get("meta") or {}).get("name") or "").strip():
            return title
        vuln_id = self.primary_vuln_id(self.vulnerability(row))
        if vuln_id and name:
            return f"{vuln_id} in {name}:{version}"
        return "Endor Labs finding"

    def primary_vuln_id(self, vulnerability):
        if not vulnerability:
            return ""
        return ((vulnerability.get("meta") or {}).get("name") or "").strip()

    def vulnerability_ids(self, vulnerability):
        """The primary identifier followed by Endor's aliases, deduplicated in order."""
        if not vulnerability:
            return []
        candidates = [self.primary_vuln_id(vulnerability)]
        aliases = (vulnerability.get("spec") or {}).get("aliases")
        if isinstance(aliases, list):
            candidates.extend(str(alias) for alias in aliases)

        ids, seen = [], set()
        for candidate in candidates:
            identifier = candidate.strip()
            if identifier and identifier not in seen:
                seen.add(identifier)
                ids.append(identifier)
        return ids

    def cvss_score(self, vulnerability):
        """
        The CVSS v3 score, falling back to the v4 base score.

        Endor publishes both, and the converter prefers v3 because that is what Finding.cvssv3_score
        holds; a v4-only advisory would otherwise import with no score at all.
        """
        if not vulnerability:
            return 0
        spec = vulnerability.get("spec") or {}
        v3 = spec.get("cvss_v3_severity")
        if isinstance(v3, dict) and (v3.get("score") or 0) > 0:
            return v3["score"]
        v4 = spec.get("cvss_v4_severity")
        if isinstance(v4, dict) and (v4.get("base_score") or 0) > 0:
            return v4["base_score"]
        return 0

    def cvss_v3_vector(self, vulnerability):
        if not vulnerability:
            return ""
        v3 = (vulnerability.get("spec") or {}).get("cvss_v3_severity")
        return (v3.get("vector") or "").strip() if isinstance(v3, dict) else ""

    def epss_probability(self, vulnerability):
        if not vulnerability:
            return 0
        epss = (vulnerability.get("spec") or {}).get("epss_score")
        return (epss.get("probability_score") or 0) if isinstance(epss, dict) else 0

    def reachability_summary(self, tags):
        """First match wins, in the connector's order of precedence."""
        present = set(tags)
        for tag, summary in REACHABILITY_SUMMARY:
            if tag in present:
                return summary
        return ""

    def describe(self, spec, vulnerability, reachability):
        parts = []
        if summary := (spec.get("summary") or "").strip():
            parts.append(inert_text(summary))
        if explanation := (spec.get("explanation") or "").strip():
            parts.append("**Explanation**: " + inert_text(explanation))
        if reachability:
            parts.append("**Reachability**: " + reachability)
        if vulnerability:
            vuln_summary = ((vulnerability.get("spec") or {}).get("summary") or "").strip()
            if vuln_summary:
                parts.append("**Vulnerability**: " + inert_text(vuln_summary))
        if epss := self.epss_probability(vulnerability):
            parts.append(f"**EPSS probability**: {epss:.4f}")
        if references := self.references(vulnerability):
            parts.append("**References**:\n" + references)
        return "\n\n".join(parts)

    def references(self, vulnerability):
        """Endor's reference URLs as an inert markdown bullet list."""
        if not vulnerability:
            return ""
        refs = (vulnerability.get("spec") or {}).get("references")
        if not isinstance(refs, list):
            return ""
        lines = [f"- {inert_text(str(ref).strip())}" for ref in refs if str(ref).strip()]
        return "\n".join(lines)

    def tags(self, spec):
        """
        Endor's finding tags and categories, humanised and deduplicated in order.

        A tag and a category can collide, which is why the connector deduplicates after joining.
        """
        tags = self.humanise(spec.get("finding_tags"), FINDING_TAG_PREFIX)
        tags.extend(self.humanise(spec.get("finding_categories"), FINDING_CATEGORY_PREFIX))

        out, seen = [], set()
        for tag in tags:
            if tag not in seen:
                seen.add(tag)
                out.append(tag)
        return out

    def humanise(self, values, prefix):
        """Strip the enum prefix, lower-case, and hyphenate; drop the _UNSPECIFIED placeholders."""
        if not isinstance(values, list):
            return []
        out = []
        for value in values:
            trimmed = str(value).strip()
            if not trimmed or trimmed.endswith(UNSPECIFIED_SUFFIX):
                continue
            human = trimmed.removeprefix(prefix).lower().replace("_", "-")
            if human:
                out.append(human)
        return out
