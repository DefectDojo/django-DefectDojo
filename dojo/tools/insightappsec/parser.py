import json
import re
from contextlib import suppress
from datetime import datetime
from html.parser import HTMLParser
from ipaddress import ip_address
from urllib.parse import urlparse

from dojo.location.feature import locations_enabled
from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

# InsightAppSec's severity enum, matched CASE-SENSITIVELY as the connector does.
SEVERITY_BY_LABEL = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFORMATIONAL": "Info",
    "SAFE": "Info",
}
DEFAULT_SEVERITY = "Info"

# Statuses the connector imports. Everything else - remediated, duplicate, ignored, false positive -
# is left out so a reimport closes it in DefectDojo.
OPEN_STATUSES = frozenset({"UNREVIEWED", "VERIFIED"})

# How many evidence entries the connector prints before summarising the rest.
MAX_VARIANCES_IN_DESCRIPTION = 3

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

# The host DefectDojo accepts: letters, digits, dot, hyphen, underscore or plus, at least two
# characters - or an IP address. See Endpoint.clean().
HOST_PATTERN = re.compile(r"^[A-Za-z0-9_\-+][A-Za-z0-9_.\-+]+$")


class _HtmlFlattener(HTMLParser):

    """
    Mirror of the connector's htmlFlattener.

    An InsightAppSec attack module's description, and the evidence it captured from the application,
    arrive as HTML. Both are flattened rather than rendered: script and style content is dropped,
    block tags become newlines, and everything else becomes plain text.
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

    The evidence InsightAppSec captures is the application's own response to an attack payload, so it
    is attacker-influenced by construction and is never passed through as markup.
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
    for needle, replacement in GO_HTML_ESCAPES:
        text = text.replace(needle, replacement)
    return text


class InsightAppSecParser:

    """
    Parses a Rapid7 InsightAppSec vulnerability export.

    Mirrors pkg/tools/insightappsec/connector/finding_converter field for field so a file import and
    an API sync deduplicate against each other instead of producing two copies of everything.

    InsightAppSec names a vulnerability only by the id of the attack module that found it, so the
    human-readable title, the rule identity and the description prose all come from a separate
    module-metadata call. An export without it produces findings called "InsightAppSec finding"; see
    extract().
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName.
        return ["Rapid7 InsightAppSec - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Rapid7 InsightAppSec - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Rapid7 InsightAppSec vulnerability export (JSON). Matches the scan type used by "
            "the InsightAppSec connector so file and API findings deduplicate. Include the attack-module "
            "metadata so findings carry a readable title and description."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Rapid7 InsightAppSec Parser.

        Mirrors the connector's Convert:
        - title: the attack module's name, plus the parameter it was found in.
        - severity: InsightAppSec's own enum, matched case-sensitively.
        - severity_justification: the raw label, so a regrade is auditable.
        - description: the URL and parameter, the module's prose, then up to three evidence entries.
        - references: the InsightAppSec UI link, then the module's reference links.
        - cvssv3_score: only when the vector really is CVSS v3.
        - unique_id_from_tool: the vulnerability id, which is also the whole deduplication hash.
        """
        return [
            "title",
            "severity",
            "severity_justification",
            "date",
            "description",
            "references",
            "cvssv3_score",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Rapid7 InsightAppSec Parser.

        Copied from the InsightAppSec block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with a hash of the unique id ALONE - no title, no severity.
        InsightAppSec's vulnerability id is stable across scans, so it is the whole identity, and
        adding a volatile field would split a finding that had merely been regraded.
        """
        return ["unique_id_from_tool"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        vulnerabilities, modules = self.extract(data)

        findings = []
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue
            if not self.is_open(vulnerability):
                # Remediated, duplicate, ignored and false-positive findings are left out so a
                # reimport closes them rather than resurrecting them.
                continue
            findings.append(self.build_finding(vulnerability, modules, test))
        return findings

    def extract(self, data):
        """
        Return the vulnerabilities and the attack-module metadata.

        InsightAppSec pages its vulnerability list under "data". The module metadata comes from a
        separate endpoint, one call per module, so an export carries it as a map keyed by module id or
        as a list of module objects.
        """
        modules = {}
        vulnerabilities = None

        if isinstance(data, list):
            vulnerabilities = data
        elif isinstance(data, dict):
            for key in ("data", "vulnerabilities"):
                if isinstance(data.get(key), list):
                    vulnerabilities = data[key]
                    break
            modules = self.index_modules(data)

        if vulnerabilities is None:
            msg = (
                "A Rapid7 InsightAppSec export is the vulnerability-list response, a JSON object with "
                f"a 'data' list; got {type(data).__name__}."
            )
            raise TypeError(msg)
        return vulnerabilities, modules

    def index_modules(self, data):
        """Attack-module metadata as a map keyed by module id, accepting a list of modules too."""
        for key in ("modules", "module_metadata"):
            source = data.get(key)
            if isinstance(source, dict):
                if isinstance(source.get("data"), list):
                    return self.index_modules({"modules": source["data"]})
                return {
                    str(identifier): module
                    for identifier, module in source.items()
                    if isinstance(module, dict)
                }
            if isinstance(source, list):
                indexed = {}
                for module in source:
                    if isinstance(module, dict) and str(module.get("id") or "").strip():
                        indexed[str(module["id"]).strip()] = module
                return indexed
        return {}

    def is_open(self, vulnerability):
        """Matched case-sensitively, as the connector's own status constants are."""
        return str(vulnerability.get("status") or "") in OPEN_STATUSES

    def variances(self, vulnerability):
        rows = vulnerability.get("variances")
        return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []

    def module(self, vulnerability, modules):
        """The metadata of the first variance whose module is present in the export."""
        for variance in self.variances(vulnerability):
            identifier = str(self.block(variance, "module").get("id") or "").strip()
            if identifier and identifier in modules:
                return modules[identifier]
        return None

    def block(self, source, key):
        value = source.get(key)
        return value if isinstance(value, dict) else {}

    def build_finding(self, vulnerability, modules, test):
        module = self.module(vulnerability, modules)
        raw_severity = str(vulnerability.get("severity") or "")

        finding = Finding(
            test=test,
            title=self.title(vulnerability, module),
            severity=SEVERITY_BY_LABEL.get(raw_severity, DEFAULT_SEVERITY),
            severity_justification=f"InsightAppSec assigned severity **{raw_severity}**.",
            description=self.describe(vulnerability, module),
            references=self.references(vulnerability),
            unique_id_from_tool=str(vulnerability.get("id") or "").strip() or None,
            vuln_id_from_tool=self.vuln_id(vulnerability, module),
            # InsightAppSec attacks a running application.
            static_finding=False,
            dynamic_finding=True,
        )

        if score := self.cvssv3_score(vulnerability):
            finding.cvssv3_score = score
        if date := self.date(vulnerability):
            finding.date = date

        self.attach_endpoint(finding, str(self.block(vulnerability, "root_cause").get("url") or "").strip())
        return finding

    def vuln_id(self, vulnerability, module):
        """
        The rule identity: the module's name, then its id, then the vulnerability id.

        The name is preferred because it is what a person recognises - "SQL Injection" rather than a
        uuid - and it is stable across InsightAppSec versions.
        """
        if module is not None and (name := str(module.get("name") or "").strip()):
            return name
        for variance in self.variances(vulnerability):
            identifier = str(self.block(variance, "module").get("id") or "").strip()
            if identifier:
                return identifier
        return str(vulnerability.get("id") or "").strip() or None

    def title(self, vulnerability, module):
        """
        "<module> in "<parameter>" parameter".

        The quotes around the parameter are the connector's, and they matter: a parameter called
        "id" is otherwise indistinguishable from prose.
        """
        name = "InsightAppSec finding"
        if module is not None and (module_name := str(module.get("name") or "").strip()):
            name = module_name
        parameter = str(self.block(vulnerability, "root_cause").get("parameter") or "").strip()
        if parameter:
            return f'{name} in "{parameter}" parameter'
        return name

    def describe(self, vulnerability, module):
        parts = []
        root = self.block(vulnerability, "root_cause")

        url = str(root.get("url") or "").strip()
        if url:
            method = str(root.get("method") or "")
            parts.append(f"**URL:** {method} {inert_text(url)}\n")
        if parameter := str(root.get("parameter") or "").strip():
            parts.append(f"**Parameter:** {inert_text(parameter)}\n")
        if module is not None and (prose := str(module.get("description") or "").strip()):
            parts.append(f"\n{inert_text(prose)}\n")

        variances = self.variances(vulnerability)
        for index, variance in enumerate(variances):
            if index >= MAX_VARIANCES_IN_DESCRIPTION:
                omitted = len(variances) - MAX_VARIANCES_IN_DESCRIPTION
                parts.append(f"\n_({omitted} further evidence entries omitted)_\n")
                break
            parts.append(self.variance_text(variance))
        return "".join(parts).rstrip("\n")

    def variance_text(self, variance):
        """
        One evidence block per variance.

        Every value is flattened: this is the application's own response to an attack payload, so it
        is the least trustworthy text in the export.
        """
        lines = ["\n**Evidence:**\n"]
        if attack_value := str(variance.get("attack_value") or "").strip():
            lines.append(f"- Attack value: {inert_text(attack_value)}\n")
        if message := str(variance.get("message") or "").strip():
            lines.append(f"- {inert_text(message)}\n")
        if proof := str(variance.get("proof") or "").strip():
            lines.append(f"- Proof: {inert_text(proof)}\n")
        return "".join(lines)

    def references(self, vulnerability):
        """
        The InsightAppSec UI link, then each variance's reference links.

        The links are taken in sorted key order - the connector sorts because a Go map has no order,
        and matching that keeps the two import paths byte-identical.
        """
        links = []
        if ui_url := str(vulnerability.get("insight_ui_url") or "").strip():
            links.append(ui_url)

        for variance in self.variances(vulnerability):
            references = self.block(variance, "references")
            for key in sorted(references):
                link = str(references[key] or "").strip()
                if link and link not in links:
                    links.append(link)
        return "\n".join(links)

    def cvssv3_score(self, vulnerability):
        """
        The score, but only when the vector really is CVSS v3.

        InsightAppSec also reports v2 vectors, and a v2 base in a v3 field would be read as a v3
        score - the same number means different things on the two scales.
        """
        score = vulnerability.get("vulnerability_score")
        if not isinstance(score, int | float) or isinstance(score, bool) or score <= 0:
            return 0.0
        if not str(vulnerability.get("vector_string") or "").startswith("CVSS:3"):
            return 0.0
        return float(score)

    def date(self, vulnerability):
        """InsightAppSec timestamps are RFC 3339; the connector keeps the first ten characters."""
        discovered = str(vulnerability.get("first_discovered") or "")
        if len(discovered) < 10:
            return None
        with suppress(ValueError):
            return datetime.strptime(discovered[:10], "%Y-%m-%d").date()
        return None

    def attach_endpoint(self, finding, url):
        """The URL the attack was delivered to."""
        if not url:
            return
        with suppress(ValueError):
            parsed = urlparse(url if "//" in url else f"//{url}")
            try:
                port = parsed.port
            except ValueError:
                return
            host = parsed.hostname or ""
            if not host or not self.usable_host(host):
                return
            if locations_enabled():
                finding.unsaved_locations.append(LocationData.url(
                    host=host, protocol=parsed.scheme or None, port=port,
                    path=parsed.path.lstrip("/"), query=parsed.query,
                ))
            else:
                # TODO: Delete this after the move to Locations
                finding.unsaved_endpoints.append(Endpoint(
                    host=host, protocol=parsed.scheme or None, port=port,
                    path=parsed.path.lstrip("/") or None, query=parsed.query or None,
                ))

    def usable_host(self, value):
        """
        Whether DefectDojo will accept this as an endpoint host.

        A host is letters, digits, dot, hyphen, underscore or plus, or an IP address. Anything else
        makes Endpoint.clean() raise, and that fails the whole import rather than the one finding.
        The URL is still in the description.
        """
        if HOST_PATTERN.match(value):
            return True
        with suppress(ValueError):
            ip_address(value)
            return True
        return False
