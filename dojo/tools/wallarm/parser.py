import json
import re
from contextlib import suppress
from datetime import UTC, datetime
from ipaddress import ip_address

from dojo.location.feature import locations_enabled
from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

SEVERITY_BY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "information": "Info",
    "informational": "Info",
    "": "Info",
}
DEFAULT_SEVERITY = "Info"

# Wallarm statuses that mean the vulnerability is not actionable.
IGNORED_STATUSES = {"closed", "falsepositive"}

# The advisory identifiers the connector's shared extractor recognises in free text.
VULNERABILITY_ID_PATTERN = re.compile(
    r"CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|GO-\d{4}-\d+|RHSA-\d{4}:\d+",
)

# The host DefectDojo accepts: letters, digits, dot, hyphen, underscore or plus, at least two
# characters - or an IP address. See Endpoint.clean().
HOST_PATTERN = re.compile(r"^[A-Za-z0-9_\-+][A-Za-z0-9_.\-+]+$")


class WallarmParser:

    """
    Parses a Wallarm vulnerabilities export.

    Mirrors pkg/tools/wallarm/converter field for field so a file import and an API sync deduplicate
    against each other instead of producing two copies of everything.

    Wallarm reports the threat level as EITHER a number or a word, in the same field, depending on
    which API answered - so severity() has to handle both. See severity().
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName. Note it does NOT follow the
        # "<Vendor> - Connectors Import" pattern, so it cannot be derived - it has to be copied.
        return ["Wallarm API Security"]

    def get_label_for_scan_types(self, scan_type):
        return "Wallarm API Security"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Wallarm vulnerabilities export (JSON), the /v1/objects/vuln response. Matches "
            "the scan type used by the Wallarm connector so file and API findings deduplicate. Closed "
            "and false-positive vulnerabilities are skipped."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Wallarm Parser.

        Mirrors the connector's Convert:
        - title: the vulnerability title, then "Wallarm: <type>", then the id.
        - severity: from the threat level, which may be a number or a word; see severity().
        - description: the type, domain, method, path, parameter and detection method, then the
          description and any additional prose.
        - mitigation: Wallarm's exploit example, which is what it offers instead of advice.
        - date: the validation time, in unix seconds.
        - unique_id_from_tool: "wallarm-<id>", falling back to the wid and then the location.
        - vuln_id_from_tool: the vulnerability type, which is Wallarm's rule identity.
        """
        return [
            "title",
            "severity",
            "date",
            "description",
            "mitigation",
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
        Return the list of fields used for deduplication in the Wallarm Parser.

        Copied from the Wallarm block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields.
        """
        return ["title", "severity", "component_name"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        findings = []
        for row in self.rows(data):
            if self.ignored(row):
                # Closed and false-positive vulnerabilities have already been dealt with in Wallarm.
                continue
            findings.append(self.build_finding(row, test))
        return findings

    def rows(self, data):
        """
        Return the vulnerabilities in the export.

        Wallarm answers with {"status": 200, "body": [...]}; a bare array is accepted too.
        """
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
        if isinstance(data, dict):
            for key in ("body", "vulnerabilities"):
                if isinstance(data.get(key), list):
                    return [row for row in data[key] if isinstance(row, dict)]

        msg = (
            "A Wallarm export is the vulnerabilities response, a JSON object with a 'body' list; got "
            f"{type(data).__name__}."
        )
        raise TypeError(msg)

    def ignored(self, row):
        return str(row.get("status") or "").strip().lower() in IGNORED_STATUSES

    def build_finding(self, row, test):
        finding = Finding(
            test=test,
            title=self.title(row),
            severity=self.severity(row),
            description=self.describe(row),
            mitigation=str(row.get("exploit_example") or ""),
            unique_id_from_tool=self.unique_id(row),
            vuln_id_from_tool=str(row.get("type") or "") or None,
            # Wallarm watches live API traffic and validates against the running service.
            static_finding=False,
            dynamic_finding=True,
            active=True,
        )
        finding.unsaved_tags = self.tags(row)

        if identifiers := self.vulnerability_ids(row):
            finding.unsaved_vulnerability_ids = identifiers
        if date := self.date(row):
            finding.date = date

        self.attach_endpoint(finding, row)
        return finding

    def unique_id(self, row):
        """
        "wallarm-<id>", falling back to the wid and then to the location.

        The location fallback is last because it is the only one that is not an id: two vulnerabilities
        of different types on one path would collide, but something stable is better than nothing.
        """
        identifier = row.get("id")
        if isinstance(identifier, int | float) and not isinstance(identifier, bool) and identifier != 0:
            return f"wallarm-{int(identifier)}"
        if wid := str(row.get("wid") or ""):
            return f"wallarm-{wid}"
        return "wallarm-" + str(row.get("domain") or "") + str(row.get("path") or "")

    def title(self, row):
        if title := str(row.get("title") or ""):
            return title
        if kind := str(row.get("type") or ""):
            return f"Wallarm: {kind}"
        identifier = row.get("id")
        number = int(identifier) if isinstance(identifier, int | float) and not isinstance(identifier, bool) else 0
        return f"Wallarm vulnerability {number}"

    def severity(self, row):
        """
        Grade the threat level, which Wallarm sends as either a number or a word.

        Which one depends on the API that answered, and the two need different ladders: the numeric
        scale runs 1-5 with 5 the most severe, while the labels are the usual words. A number is
        graded numerically even if it arrives as a JSON float, matching the connector's own decoder.
        """
        threat = row.get("threat")
        if isinstance(threat, bool):
            return DEFAULT_SEVERITY
        if isinstance(threat, int | float):
            value = int(threat)
            if value >= 5:
                return "Critical"
            if value == 4:
                return "High"
            if value == 3:
                return "Medium"
            if value == 2:
                return "Low"
            return "Info"
        label = str(threat or "").strip().lower()
        return SEVERITY_BY_LABEL.get(label, DEFAULT_SEVERITY)

    def describe(self, row):
        """
        The location fields as single-newline lines, then the prose sections.

        The prose is separated by a blank line because it is paragraphs rather than fields - the
        connector's own distinction.
        """
        lines = []
        for label, key in (("Type", "type"), ("Domain", "domain"), ("Method", "method"),
                           ("Path", "path"), ("Parameter", "parameter"),
                           ("Detection method", "detection_method")):
            value = str(row.get(key) or "")
            if value:
                lines.append(f"**{label}:** {value}")
        text = "\n".join(lines)

        for label, key in (("Description", "description"), ("Additional", "additional")):
            value = str(row.get(key) or "")
            if not value:
                continue
            if text:
                text += "\n\n"
            text += f"**{label}:**\n{value}"
        return text.strip()

    def vulnerability_ids(self, row):
        """
        Identifiers found in the title, type, template, description and additional text.

        The connector's shared extractor SORTS these and drops case-insensitive duplicates, so the
        same is done here rather than preserving document order.
        """
        prose = "|".join([
            str(row.get("title") or ""),
            str(row.get("type") or ""),
            str(row.get("template") or ""),
            str(row.get("description") or ""),
            str(row.get("additional") or ""),
        ])
        found = sorted(VULNERABILITY_ID_PATTERN.findall(prose))

        identifiers = []
        for candidate in found:
            if not identifiers or identifiers[-1].lower() != candidate.lower():
                identifiers.append(candidate)
        return identifiers

    def date(self, row):
        """Wallarm timestamps the validation in unix SECONDS."""
        value = row.get("validate_time")
        if isinstance(value, int | float) and not isinstance(value, bool) and value > 0:
            with suppress(OSError, OverflowError, ValueError):
                return datetime.fromtimestamp(value, tz=UTC).date()
        return None

    def tags(self, row):
        tags = []
        for value in (row.get("type"), row.get("status")):
            text = str(value or "")
            if text:
                tags.append(text)
        return tags

    def attach_endpoint(self, finding, row):
        """
        Record the domain, plus the path when Wallarm reported an absolute one.

        The connector only appends a path beginning with "/", because anything else is not a path -
        Wallarm uses that field for a parameter location on some vulnerability types.
        """
        host = str(row.get("domain") or "").strip()
        if not host or not self.usable_host(host):
            return
        path = str(row.get("path") or "")
        path = path.lstrip("/") if path.startswith("/") else ""

        if locations_enabled():
            finding.unsaved_locations.append(LocationData.url(host=host, path=path))
        else:
            # TODO: Delete this after the move to Locations
            finding.unsaved_endpoints.append(Endpoint(host=host, path=path or None))

    def usable_host(self, value):
        """
        Whether DefectDojo will accept this as an endpoint host.

        A host is letters, digits, dot, hyphen, underscore or plus, or an IP address. Anything else
        makes Endpoint.clean() raise, and that fails the whole import rather than the one finding. The
        domain is still in the description.
        """
        if HOST_PATTERN.match(value):
            return True
        with suppress(ValueError):
            ip_address(value)
            return True
        return False
