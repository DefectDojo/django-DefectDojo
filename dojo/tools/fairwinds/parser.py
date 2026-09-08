import json
import re
from html.parser import HTMLParser

from dojo.models import Finding

# Fairwinds scores severity as a FLOAT from 0.0 to 1.0, not a word. These are the connector's
# breakpoints; anything below the Low floor is Info.
SEVERITY_CRITICAL_FLOOR = 0.9
SEVERITY_HIGH_FLOOR = 0.7
SEVERITY_MEDIUM_FLOOR = 0.4
SEVERITY_LOW_FLOOR = 0.1
DEFAULT_SEVERITY = "Info"

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

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
    """Flatten text to escaped plain text, as the connector's InertText does."""
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


class FairwindsParser:

    """
    Parses a Fairwinds Insights action-items export.

    Mirrors pkg/tools/fairwinds/converter field for field so a file import and an API sync deduplicate
    against each other instead of producing two copies of everything.

    Fairwinds aggregates several Kubernetes scanners - Polaris, Trivy, OPA, kube-bench - into one
    action-item stream, and its JSON keys are PascalCase ("Title", "Severity", "ResourceKind").
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanType().
        return ["Fairwinds Insights - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Fairwinds Insights - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Fairwinds Insights action-items export (JSON). Matches the scan type used by "
            "the Fairwinds Insights connector so file and API findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Fairwinds Parser.

        Mirrors the connector's ActionItemToFinding:
        - title: the action item's title, falling back to "Fairwinds action item <id>".
        - severity: from Fairwinds' 0.0-1.0 severity score; see severity().
        - description: the description, then the Kubernetes resource, image, event type and notes.
        - mitigation: the item's remediation advice.
        - component_name / component_version: the container image and tag, else the resource name.
        - active / is_mitigated: from the item's Fixed flag.
        - unique_id_from_tool: the Fairwinds action-item id.
        """
        return [
            "title",
            "severity",
            "description",
            "mitigation",
            "component_name",
            "component_version",
            "unique_id_from_tool",
            "tags",
            "active",
            "is_mitigated",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Fairwinds Parser.

        Copied from the Fairwinds Insights block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields.
        """
        return ["title", "severity", "component_name"]

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
        """Fairwinds' action-items endpoint returns a bare array; envelopes are accepted too."""
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("ActionItems", "actionItems", "items", "data"):
                if isinstance(data.get(key), list):
                    return data[key]
        msg = (
            "A Fairwinds Insights export is a JSON array of action items, or an object with an "
            f"'ActionItems' list; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def build_finding(self, item, test):
        fixed = bool(item.get("Fixed"))
        name, version = self.component(item)

        finding = Finding(
            test=test,
            title=self.title(item),
            severity=self.severity(item.get("Severity")),
            description=self.describe(item),
            component_name=name or None,
            component_version=version or None,
            unique_id_from_tool=str(item.get("ID")),
            # Fairwinds tracks whether the item has been fixed, so a fixed item is imported closed
            # rather than sitting in the open queue.
            active=not fixed,
            is_mitigated=fixed,
            # Fairwinds reads cluster manifests and images, not a running service.
            static_finding=True,
            dynamic_finding=False,
        )

        remediation = (item.get("Remediation") or "").strip()
        if remediation:
            finding.mitigation = inert_text(remediation)

        cves = self.cves(item)
        if cves:
            finding.unsaved_vulnerability_ids = cves
        finding.unsaved_tags = self.tags(item)
        return finding

    def title(self, item):
        title = (item.get("Title") or "").strip()
        if title:
            return inert_text(title)
        return f"Fairwinds action item {item.get('ID')}"

    def severity(self, score):
        """
        Grade Fairwinds' 0.0-1.0 severity score.

        It is a normalised float, not a word and not a CVSS score, so the breakpoints are Fairwinds'
        own: 0.9 Critical, 0.7 High, 0.4 Medium, 0.1 Low, below that Info.
        """
        try:
            value = float(score)
        except (TypeError, ValueError):
            return DEFAULT_SEVERITY
        if value >= SEVERITY_CRITICAL_FLOOR:
            return "Critical"
        if value >= SEVERITY_HIGH_FLOOR:
            return "High"
        if value >= SEVERITY_MEDIUM_FLOOR:
            return "Medium"
        if value >= SEVERITY_LOW_FLOOR:
            return "Low"
        return DEFAULT_SEVERITY

    def describe(self, item):
        parts = []
        description = (item.get("Description") or "").strip()
        if description:
            parts.append(inert_text(description))
        if resource := self.resource_line(item):
            parts.append(f"**Resource:** {resource}")
        if image := self.image_ref(item):
            parts.append(f"**Image:** {inert_text(image)}")
        if event_type := (item.get("EventType") or "").strip():
            parts.append(f"**Event type:** {inert_text(event_type)}")
        if notes := (item.get("Notes") or "").strip():
            parts.append(f"**Notes:** {inert_text(notes)}")
        return "\n\n".join(parts)

    def resource_line(self, item):
        """
        The Kubernetes coordinates as "namespace/kind/name", with the container appended.

        Any of the three segments may be missing, and the container qualifier only appears when
        Fairwinds identified one.
        """
        segments = [
            segment for segment in (
                (item.get("ResourceNamespace") or "").strip(),
                (item.get("ResourceKind") or "").strip(),
                (item.get("ResourceName") or "").strip(),
            ) if segment
        ]
        line = "/".join(segments)
        container = (item.get("ResourceContainer") or "").strip()
        if container:
            line = f"{line} (container: {container})".strip()
        return inert_text(line) if line else ""

    def image_ref(self, item):
        name = (item.get("ImageName") or "").strip()
        if not name:
            return ""
        tag = (item.get("ImageTag") or "").strip()
        return f"{name}:{tag}" if tag else name

    def component(self, item):
        """
        The container image is the component when there is one; otherwise the Kubernetes resource.

        A Trivy image finding and a Polaris manifest finding are both action items, so the component
        has to come from whichever the item is about.
        """
        name = (item.get("ImageName") or "").strip()
        if name:
            return name, (item.get("ImageTag") or "").strip()
        return (item.get("ResourceName") or "").strip(), ""

    def cves(self, item):
        """Fairwinds has no CVE field; the connector scans the title and description."""
        found, seen = [], set()
        for source in (item.get("Title") or "", item.get("Description") or ""):
            for cve in CVE_PATTERN.findall(str(source)):
                upper = cve.upper()
                if upper not in seen:
                    seen.add(upper)
                    found.append(upper)
        return found

    def tags(self, item):
        """
        The connector's tag set, deduplicated in order.

        Note the cluster tag is added unconditionally, so an item with no cluster still gets a bare
        "cluster:" tag - reproduced rather than tidied.
        """
        out, seen = [], set()

        def add(tag):
            tag = (tag or "").strip()
            if tag and tag not in seen:
                seen.add(tag)
                out.append(tag)

        if report_type := (item.get("ReportType") or "").strip():
            add(f"tool:{report_type}")
        if category := (item.get("Category") or "").strip():
            add(f"category:{category.lower()}")
        add("cluster:" + (item.get("Cluster") or "").strip())
        if namespace := (item.get("ResourceNamespace") or "").strip():
            add(f"namespace:{namespace}")
        if event_type := (item.get("EventType") or "").strip():
            add(f"event:{event_type}")
        tags = item.get("Tags")
        if isinstance(tags, list):
            for tag in tags:
                add(str(tag))
        return out
