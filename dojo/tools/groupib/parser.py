import json
import re
from contextlib import suppress
from datetime import date as _date
from ipaddress import ip_address
from urllib.parse import urlparse

from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

# Group-IB writes its severity as a phrase, e.g. "Critical severity", so it is matched by CONTAINMENT
# in this order rather than by equality.
SEVERITY_KEYWORDS = (
    ("critical", "Critical"),
    ("high", "High"),
    ("medium", "Medium"),
    ("low", "Low"),
    ("info", "Info"),
)
DEFAULT_SEVERITY = "Info"

# The ASM issue lifecycle. "Detected" and "Under review" are open.
STATUS_SOLVED = "solved"
STATUS_FALSE_POSITIVE = "false positive"
STATUS_IGNORED = "ignored"

NO_DETAILS = "No additional details were provided by Group-IB ASM."

# The host DefectDojo accepts: letters, digits, dot, hyphen, underscore or plus, at least two
# characters - or an IP address. See Endpoint.clean().
HOST_PATTERN = re.compile(r"^[A-Za-z0-9_\-+][A-Za-z0-9_.\-+]+$")


class GroupibParser:

    """
    Parses a Group-IB ASM (Attack Surface Management) issue export.

    Mirrors pkg/tools/groupib/connector/issue_converter field for field so a file import and an API sync
    deduplicate against each other instead of producing two copies of everything.

    Two fields are both called "status" and mean entirely different things: the issue's own status is
    its LIFECYCLE state (Detected, Solved, Ignored, False positive), while the status inside its body is
    the SEVERITY label. Reading one for the other would grade every finding Info and leave every solved
    issue open; see severity() and apply_status().

    ASM findings come from external scanning, so they are dynamic. The affected asset becomes an
    ENDPOINT when it looks like a host, an address or a URL, and the COMPONENT otherwise - Group-IB
    reports software names and SSL descriptors in the same field; see add_asset().
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName.
        return ["Group-IB ASM - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Group-IB ASM - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Group-IB ASM issue export (JSON). Matches the scan type used by the Group-IB "
            "connector so file and API findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Group-IB Parser.

        Mirrors the connector's ConvertIssue:
        - title: the issue type, then its reason, then its category, then the issue id.
        - severity: the SEVERITY label inside the body; see severity().
        - description: the category, type, asset and its status, the reason, details and context.
        - date: when the issue was first seen.
        - active / is_mitigated / false_p / out_of_scope: the issue's LIFECYCLE status.
        - tags: the MITRE ATT&CK techniques, as "mitre-attack:<technique>".
        - unique_id_from_tool: the issue id; vuln_id_from_tool: the issue type.
        """
        return [
            "title",
            "severity",
            "description",
            "component_name",
            "date",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "tags",
            "active",
            "is_mitigated",
            "false_p",
            "out_of_scope",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Group-IB Parser.

        Copied from the Group-IB ASM block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields - only the title and the severity, since
        an ASM issue has neither a file nor a package to hash.
        """
        return ["title", "severity"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        return [self.build_finding(row, test) for row in self.rows(data)]

    def rows(self, data):
        """
        Return the issues in the export.

        Group-IB answers {"items": [...]}, and its own client tolerates several spellings of that key,
        so all of them are accepted. A bare array works too.
        """
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
        if isinstance(data, dict):
            for key in ("items", "data", "results", "issues"):
                if isinstance(data.get(key), list):
                    return [row for row in data[key] if isinstance(row, dict)]

        msg = (
            "A Group-IB ASM export is the issues response, a JSON object with an 'items' list; got "
            f"{type(data).__name__}."
        )
        raise TypeError(msg)

    def build_finding(self, row, test):
        body = self.block(row, "body")

        finding = Finding(
            test=test,
            title=self.title(row, body),
            severity=self.severity(body),
            description=self.describe(body),
            unique_id_from_tool=str(row.get("id") or "") or None,
            vuln_id_from_tool=str(body.get("type") or "") or None,
            # ASM findings come from external scanning, so they are observed rather than read.
            static_finding=False,
            dynamic_finding=True,
        )
        if tags := self.mitre_tags(body.get("alertMitreInfo")):
            finding.unsaved_tags = tags
        if date := self.date(row.get("firstSeen")):
            finding.date = date

        self.add_asset(finding, str(body.get("asset") or "").strip())
        self.apply_status(finding, str(row.get("status") or ""))
        return finding

    def block(self, row, key):
        if not isinstance(row, dict):
            return {}
        value = row.get(key)
        return value if isinstance(value, dict) else {}

    def title(self, row, body):
        for key in ("type", "reason", "category"):
            if value := str(body.get(key) or ""):
                return value
        return f"Group-IB ASM issue {row.get('id') or ''}"

    def severity(self, body):
        """
        The severity label inside the issue body - NOT the issue's own status field.

        Group-IB writes it as a phrase, "Critical severity", so it is matched by containment. The order
        matters: "critical" is tested before "high" so a label naming both is graded by the worse one.
        An unrecognised label is Info, which the connector logs a warning for.
        """
        label = str(body.get("status") or "").lower()
        for keyword, severity in SEVERITY_KEYWORDS:
            if keyword in label:
                return severity
        return DEFAULT_SEVERITY

    def describe(self, body):
        """
        The informative fields, one per line.

        An issue with none of them says so rather than arriving with an empty description, which would
        read as though the data had been lost in transit.
        """
        fields = (
            ("Category", "category"),
            ("Type", "type"),
            ("Asset", "asset"),
            ("Asset status", "assetStatus"),
            ("Asset discovered", "assetDiscovered"),
            ("Reason", "reason"),
            ("Details", "descriptions"),
            ("Context", "context"),
        )
        lines = [
            f"**{label}:** {value}"
            for label, key in fields
            if (value := str(body.get(key) or "").strip())
        ]
        return "\n".join(lines) or NO_DETAILS

    def mitre_tags(self, mitre):
        """
        The MITRE ATT&CK techniques, as "mitre-attack:<technique>", sorted.

        Group-IB sends them as a MAP keyed by technique, so the keys are the techniques and the sort is
        what makes the order stable.
        """
        if not isinstance(mitre, dict):
            return []
        return sorted(f"mitre-attack:{technique}" for technique in mitre if technique)

    def apply_status(self, finding, status):
        """
        The issue's LIFECYCLE status - not the severity label in its body.

        "Detected", "Under review" and anything unrecognised stay ACTIVE, which is the safe direction to
        be wrong in. The three closing states are distinguished because they mean different things: a
        solved issue was fixed, an ignored one was accepted, and a false positive was never real.
        """
        normalised = status.strip().lower()
        if normalised == STATUS_SOLVED:
            finding.active = False
            finding.is_mitigated = True
        elif normalised == STATUS_FALSE_POSITIVE:
            finding.active = False
            finding.false_p = True
        elif normalised == STATUS_IGNORED:
            finding.active = False
            finding.out_of_scope = True
        else:
            finding.active = True

    def add_asset(self, finding, asset):
        """
        The affected asset - an endpoint when it names one, the component otherwise.

        Group-IB reports software names and SSL or login-form descriptors in the same field as hosts and
        URLs, so anything that is not host-shaped becomes the component instead. Recording a software
        name as an endpoint would make Endpoint.clean() raise and fail the whole import.
        """
        if not asset:
            return

        host, port, protocol = self.endpoint_parts(asset)
        if not host:
            finding.component_name = asset
            return

        if settings.V3_FEATURE_LOCATIONS:
            finding.unsaved_locations.append(
                LocationData.url(host=host, port=port, protocol=protocol),
            )
        else:
            # TODO: Delete this after the move to Locations
            finding.unsaved_endpoints.append(Endpoint(host=host, port=port, protocol=protocol))

    def endpoint_parts(self, asset):
        """
        Split a host-shaped asset into host, port and protocol; return no host when it is not one.

        Group-IB sends a bare host or address with NO scheme. The connector prefixes "//" so
        Endpoint.from_uri reads it as an authority rather than a path - this builds the endpoint from
        its parts instead, which reaches the same result without the string trick.
        """
        if any(character.isspace() for character in asset):
            return "", None, None

        if "://" in asset:
            parsed = urlparse(asset)
            host = parsed.hostname or ""
            if not host or not self.usable_host(host):
                return "", None, None
            with suppress(ValueError):
                return host, parsed.port, parsed.scheme or None
            return host, None, parsed.scheme or None

        # An already scheme-relative value: the connector leaves it as it is, because that is exactly
        # the form its "//" prefix produces. The authority is what follows the slashes.
        asset = asset.removeprefix("//")
        if not asset:
            return "", None, None

        host, port = self.split_port(asset)
        if not host:
            return "", None, None

        with suppress(ValueError):
            ip_address(host)
            return host, port, None

        # A domain needs a dot and an alphabetic top-level label; a software name like
        # "OpenSSL 1.0.2" has neither, and one with a path separator is not a host at all.
        if "/" in host or "\\" in host or "." not in host:
            return "", None, None
        tld = host.rsplit(".", 1)[-1]
        if len(tld) >= 2 and tld.isalpha() and self.usable_host(host):
            return host, port, None
        return "", None, None

    def split_port(self, asset):
        """"host:port" split, tolerating a bare IPv6 address, which has colons of its own."""
        if asset.count(":") == 1:
            host, _, port = asset.partition(":")
            if port.isdigit():
                return host, int(port)
            return asset, None
        return asset, None

    def usable_host(self, value):
        """A host is letters, digits, dot, hyphen, underscore or plus, or an IP address."""
        if HOST_PATTERN.match(value):
            return True
        with suppress(ValueError):
            ip_address(value)
            return True
        return False

    def date(self, value):
        """
        When the issue was first seen, as a date.

        The connector parses this strictly and returns nothing when it cannot, which leaves the import
        default in place rather than failing the file.
        """
        text = str(value or "").strip()
        if len(text) < 10:
            return None
        with suppress(ValueError):
            return _date.fromisoformat(text[:10])
        return None
