import json
from contextlib import suppress

from dojo.models import Finding

SEVERITY_BY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
DEFAULT_SEVERITY = "Info"

# Qwiet carries its interesting metadata as key/value tags rather than fields.
TAG_REACHABILITY = "reachability"
TAG_CVE = "cve"
TAG_PACKAGE_URL = "package_url"
TAG_CVSS_SCORE = "cvss_score"
TAG_CWE_CATEGORY = "cwe_category"

TYPE_OSS_VULN = "oss_vuln"
REACHABLE = "reachable"


class QwietParser:

    """
    Parses a Qwiet AI (formerly ShiftLeft) findings export.

    Mirrors pkg/tools/qwiet/connector/finding_converter field for field so a file import and an API sync
    deduplicate against each other instead of producing two copies of everything.

    Qwiet reports most of what matters as key/value TAGS rather than fields - the CVE, the package URL,
    the CVSS score, the CWE category and the reachability verdict all live there - so the parser reads
    them out by key; see tag_value().
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName. Note it does NOT follow the
        # "<Vendor> - Connectors Import" pattern, so it cannot be derived - it has to be copied.
        return ["Qwiet Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Qwiet Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Qwiet AI findings export (JSON), the findings response for an app. Matches the "
            "scan type used by the Qwiet connector so file and API findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Qwiet Parser.

        Mirrors the connector's Convert:
        - title: the finding title, then its category, then the id.
        - severity: Qwiet's own label; anything unrecognised is Info.
        - severity_justification: Qwiet's reachability verdict, spelled out; see justification().
        - description: the type, category, OWASP category, the source and sink methods, the file
          locations, then Qwiet's prose.
        - cwe / cvssv3_score / unsaved_vulnerability_ids: read out of the tags.
        - component_name / component_version: parsed from the package URL tag.
        - file_path / line: the first file location, which is "<path>:<line>".
        - unique_id_from_tool: "qwiet-<internal id>", falling back to the finding id.
        """
        return [
            "title",
            "severity",
            "severity_justification",
            "description",
            "cwe",
            "cvssv3_score",
            "component_name",
            "component_version",
            "file_path",
            "line",
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
        Return the list of fields used for deduplication in the Qwiet Parser.

        Copied from the Qwiet block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. Qwiet reports both code findings and
        dependency findings, which is why the hash spans a file path, a CWE and a component: a given
        finding has one or the other, and the unused half hashes as empty.
        """
        return ["title", "severity", "file_path", "cwe", "component_name"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        return [self.build_finding(row, test) for row in self.rows(data)]

    def rows(self, data):
        """
        Return the findings in the export.

        Qwiet wraps every response as {"ok": true, "response": [...]}; a bare array is accepted too.
        """
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
        if isinstance(data, dict):
            for key in ("response", "findings"):
                if isinstance(data.get(key), list):
                    return [row for row in data[key] if isinstance(row, dict)]

        msg = (
            "A Qwiet export is the findings response, a JSON object with a 'response' list; got "
            f"{type(data).__name__}."
        )
        raise TypeError(msg)

    def build_finding(self, row, test):
        finding = Finding(
            test=test,
            title=self.title(row),
            severity=self.severity(row),
            description=self.describe(row),
            cwe=self.cwe(row),
            unique_id_from_tool=self.unique_id(row),
            vuln_id_from_tool=self.vuln_id(row),
            # Qwiet analyses code and dependencies; nothing is exercised.
            static_finding=True,
            dynamic_finding=False,
            active=True,
        )
        finding.cvssv3_score = self.score(row)
        finding.unsaved_tags = self.tags(row)

        if cve := self.tag_value(row, TAG_CVE):
            finding.unsaved_vulnerability_ids = [cve]

        name, version = self.component(self.tag_value(row, TAG_PACKAGE_URL))
        if name:
            finding.component_name = name
            finding.component_version = version or None

        path, line = self.file_location(row)
        if path:
            finding.file_path = path
            finding.line = line or None

        if justification := self.justification(row):
            finding.severity_justification = justification
        return finding

    def unique_id(self, row):
        """Qwiet's internal id is stable across scans; the display id is the fallback."""
        for key in ("internal_id", "id"):
            if value := str(row.get(key) or ""):
                return f"qwiet-{value}"
        return "qwiet-"

    def vuln_id(self, row):
        """The internal id, then the category - the rule rather than this instance of it."""
        for key in ("internal_id", "category"):
            if value := str(row.get(key) or ""):
                return value
        return None

    def title(self, row):
        for key in ("title", "category"):
            if value := str(row.get(key) or ""):
                return value
        return "Qwiet finding " + str(row.get("id") or "")

    def severity(self, row):
        label = str(row.get("severity") or "").strip().lower()
        return SEVERITY_BY_LABEL.get(label, DEFAULT_SEVERITY)

    def details(self, row):
        value = row.get("details")
        return value if isinstance(value, dict) else {}

    def describe(self, row):
        """
        The classification, then the data-flow path, then Qwiet's prose.

        The source and sink methods are the two ends of the flow Qwiet traced, which is the part a
        reviewer needs to judge whether the path is real.
        """
        lines = []
        for label, key in (("Type", "type"), ("Category", "category"), ("OWASP", "owasp_category")):
            value = str(row.get(key) or "")
            if value:
                lines.append(f"**{label}:** {value}")

        details = self.details(row)
        for label, key in (("Source", "source_method"), ("Sink", "sink_method")):
            value = str(details.get(key) or "")
            if value:
                lines.append(f"**{label}:** {value}")
        if locations := self.file_locations(row):
            lines.append("**Locations:** " + ", ".join(locations))

        text = "\n".join(lines)
        if description := str(row.get("description") or ""):
            if text:
                text += "\n\n"
            text += description
        return text.strip()

    def file_locations(self, row):
        rows = self.details(row).get("file_locations")
        if not isinstance(rows, list):
            return []
        return [str(item).strip() for item in rows if str(item or "").strip()]

    def file_location(self, row):
        """
        The first file location, which Qwiet formats as "<path>:<line>".

        Only the first is used for the fields; the whole list is in the description, because a data-flow
        finding legitimately spans several files and DefectDojo has one file_path.
        """
        locations = self.file_locations(row)
        if not locations:
            return "", 0
        location = locations[0]
        path, separator, line = location.partition(":")
        if not separator:
            return location, 0
        with suppress(ValueError):
            return path, int(line)
        return path, 0

    def tag_value(self, row, key):
        """Qwiet's tags are a list of {"key": ..., "value": ...} objects, not a map."""
        for tag in row.get("tags") or []:
            if isinstance(tag, dict) and str(tag.get("key") or "") == key:
                return str(tag.get("value") or "").strip()
        return ""

    def cwe(self, row):
        trimmed = self.tag_value(row, TAG_CWE_CATEGORY).upper().removeprefix("CWE-")
        with suppress(ValueError):
            return int(trimmed)
        return 0

    def score(self, row):
        with suppress(ValueError):
            return float(self.tag_value(row, TAG_CVSS_SCORE))
        return 0.0

    def component(self, purl):
        """
        Read the package name and version off a package URL.

        Only the last path segment matters - "pkg:maven/org.example/lib@1.2.3" is lib 1.2.3 - because
        the namespace before it is the group, not the artefact DefectDojo matches on.
        """
        if not purl:
            return "", ""
        last = purl.rsplit("/", 1)[-1]
        name, separator, version = last.partition("@")
        if not separator:
            return last, ""
        return name, version

    def is_reachable(self, row):
        """
        Whether Qwiet traced a path from application input to the vulnerable code.

        A dependency finding with related findings is reachable even without the tag: the related
        findings ARE the path Qwiet found through the application.
        """
        if self.tag_value(row, TAG_REACHABILITY).lower() == REACHABLE:
            return True
        return str(row.get("type") or "") == TYPE_OSS_VULN and bool(row.get("related_findings"))

    def justification(self, row):
        """
        Qwiet's reachability verdict, spelled out.

        Reachability is the whole point of the tool, and it does not change the severity here - it is
        recorded as the justification so a reviewer can see why two findings of equal severity are not
        equally urgent.
        """
        value = self.tag_value(row, TAG_REACHABILITY)
        if not value and str(row.get("type") or "") == TYPE_OSS_VULN and row.get("related_findings"):
            value = REACHABLE
        if not value:
            return ""
        if self.is_reachable(row):
            return (
                "Qwiet marks this finding as reachable: an attacker-controlled data-flow path "
                "connects application input to the vulnerable code."
            )
        return f"Qwiet marks this finding as {value}."

    def tags(self, row):
        tags = []
        for key in ("type", "owasp_category"):
            value = str(row.get(key) or "")
            if value:
                tags.append(value)
        if reachability := self.tag_value(row, TAG_REACHABILITY):
            tags.append(f"reachability:{reachability}")
        elif self.is_reachable(row):
            tags.append("reachability:reachable")
        return tags
