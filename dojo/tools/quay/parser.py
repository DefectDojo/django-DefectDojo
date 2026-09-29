import json
from html.parser import HTMLParser

from dojo.models import Finding

# Quay's scanner is Clair, which grades "Defcon1" above Critical. Both land on Critical, which is the
# highest DefectDojo has.
SEVERITY_MAP = {
    "critical": "Critical",
    "defcon1": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
DEFAULT_SEVERITY = "Info"

# Clair supplies no impact assessment, and the connector says so rather than leaving it blank.
IMPACT_NOT_PROVIDED = "No impact provided"

# The connector's HTML flattener, duplicated per tool in the connectors repo rather than shared.
BLOCK_TAGS = frozenset({
    "br", "p", "div", "li", "tr", "ul", "ol", "table", "blockquote",
    "h1", "h2", "h3", "h4", "h5", "h6",
})
DROPPED_TAGS = frozenset({"script", "style"})
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
    Flatten advisory text to escaped plain text, as the connector's InertText does.

    Clair advisory text comes from upstream distro trackers, so it is never passed through as markup.
    """
    if not raw_html:
        return ""
    flattener = _HtmlFlattener()
    flattener.feed(raw_html)
    flattener.close()
    return go_escape(collapse_whitespace(flattener.text()))


def collapse_whitespace(text):
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


class QuayParser:

    """
    Parses a Quay container security report.

    Mirrors pkg/tools/quay/connector/converter.go field for field so a file import and an API sync
    deduplicate against each other instead of producing two copies of everything.

    Quay's scanner is Clair, so the report nests vulnerabilities under the features (packages) they
    affect, and the JSON keys are Capitalised - "Layer", "Features", "Name". One finding per
    feature/vulnerability pair.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanType().
        return ["Quay - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Quay - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Quay container security report (JSON, Clair-shaped). Matches the scan type "
            "used by the Quay connector so file and API findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Quay Parser.

        Mirrors the connector's Convert:
        - title: "<advisory id> - (<feature>, <version>)".
        - severity: Clair's severity word, with Defcon1 also Critical.
        - description: the advisory text, then the feature, version, fix, namespace, CVE and tag.
        - component_name / component_version: the vulnerable feature and its version.
        - impact: always "No impact provided" - Clair supplies none.
        - mitigation: Clair's FixedBy, when it has one.
        - references: Clair's advisory link.
        - unique_id_from_tool: the advisory id concatenated with the feature name.
        - vuln_id_from_tool: the advisory id.
        """
        return [
            "title",
            "severity",
            "description",
            "component_name",
            "component_version",
            "impact",
            "mitigation",
            "references",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Quay Parser.

        Copied from the Quay block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields.
        """
        return ["title", "severity", "component_name", "component_version"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        features, tag_name = self.extract(data)

        findings = {}
        for feature in features:
            if not isinstance(feature, dict):
                continue
            vulnerabilities = feature.get("Vulnerabilities")
            if not isinstance(vulnerabilities, list):
                continue
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    continue
                finding = self.build_finding(feature, vulnerability, tag_name, test)
                findings.setdefault(finding.unique_id_from_tool, finding)
        return list(findings.values())

    def extract(self, data):
        """
        Return the Clair features and the image tag.

        Quay wraps the Clair output in data.Layer.Features. The tag is not in the report body - the
        connector supplies it from the tag it scanned - so an export should carry it alongside.
        """
        if isinstance(data, list):
            return data, ""
        if isinstance(data, dict):
            tag_name = data.get("tag") or data.get("tag_name") or ""
            layer = ((data.get("data") or {}) if isinstance(data.get("data"), dict) else {}).get("Layer")
            if isinstance(layer, dict) and isinstance(layer.get("Features"), list):
                return layer["Features"], tag_name
            # A bare Layer, or an already-unwrapped features list.
            if isinstance(data.get("Layer"), dict) and isinstance(data["Layer"].get("Features"), list):
                return data["Layer"]["Features"], tag_name
            if isinstance(data.get("Features"), list):
                return data["Features"], tag_name
        msg = (
            "A Quay security report is a JSON object with data.Layer.Features (the Clair shape); got "
            f"{type(data).__name__}."
        )
        raise TypeError(msg)

    def build_finding(self, feature, vulnerability, tag_name, test):
        name = feature.get("Name") or ""
        version = feature.get("Version") or ""
        advisory = vulnerability.get("Name") or ""

        finding = Finding(
            test=test,
            title=f"{advisory} - ({name}, {version})",
            severity=SEVERITY_MAP.get(
                (vulnerability.get("Severity") or "").strip().lower(), DEFAULT_SEVERITY,
            ),
            description=self.describe(feature, vulnerability, tag_name, name, version, advisory),
            component_name=name or None,
            component_version=version or None,
            # Clair reports no impact assessment at all.
            impact=IMPACT_NOT_PROVIDED,
            # The connector concatenates these with no separator.
            unique_id_from_tool=f"{advisory}{name}",
            vuln_id_from_tool=advisory or None,
            # A registry scan reads a built image, never a running service.
            static_finding=True,
            dynamic_finding=False,
        )

        fixed_by = (vulnerability.get("FixedBy") or "").strip()
        if fixed_by:
            finding.mitigation = inert_text(fixed_by)
        link = (vulnerability.get("Link") or "").strip()
        if link:
            finding.references = inert_text(link)
        if advisory:
            finding.unsaved_vulnerability_ids = [advisory]
        return finding

    def describe(self, feature, vulnerability, tag_name, name, version, advisory):
        """
        The connector's block, in its order.

        Note the fix, namespace and CVE lines are written even when empty, which is why they are not
        conditional here - a file import has to read the same way as an API sync.
        """
        description = inert_text(vulnerability.get("Description"))
        description += f"\n**Vulnerable feature:** {inert_text(name)}"
        description += f"\n**Vulnerable version:** {inert_text(version)}"
        description += f"\n**Fixed by:** {inert_text(vulnerability.get('FixedBy'))}"
        description += f"\n**Namespace:** {inert_text(vulnerability.get('NamespaceName'))}"
        description += f"\n**CVE:** {inert_text(advisory)}"
        if tag_name:
            description += f"\n**Image tag:** {inert_text(tag_name)}"
        return description
