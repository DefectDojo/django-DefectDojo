import json
import re
from contextlib import suppress
from datetime import datetime
from ipaddress import ip_address
from urllib.parse import urlparse

from dojo.location.feature import locations_enabled
from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

SEVERITY_BY_NAME = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}
# Holm's numeric scale, used when the name is missing or unrecognised. 4 is the most severe.
SEVERITY_BY_LEVEL = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info"}
DEFAULT_SEVERITY = "Info"

# Statuses that mean Holm no longer sees the vulnerability.
CLOSED_STATUSES = {"fixed", "closed", "resolved"}

# Holm splits its scanning into a network class and a web class. Only the web class exercises a running
# application, which is why the class decides static versus dynamic.
CLASS_NET = "net"
CLASS_WEB = "web"

# The host DefectDojo accepts: letters, digits, dot, hyphen, underscore or plus, at least two
# characters - or an IP address. See Endpoint.clean().
HOST_PATTERN = re.compile(r"^[A-Za-z0-9_\-+][A-Za-z0-9_.\-+]+$")


class HolmSecurityParser:

    """
    Parses a Holm Security vulnerabilities export.

    Mirrors pkg/tools/holmsecurity/connector/finding_converter field for field so a file import and an
    API sync deduplicate against each other instead of producing two copies of everything.

    Holm scans two ways - a network class and a web class - and the connector treats only the web class
    as dynamic. The class is not on the vulnerability row itself, so an export has to say which it is;
    see extract().
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName. Note it does NOT follow the
        # "<Vendor> - Connectors Import" pattern, so it cannot be derived - it has to be copied.
        return ["Holm Security Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Holm Security Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Holm Security vulnerabilities export (JSON). Matches the scan type used by the "
            "Holm Security connector so file and API findings deduplicate. Say whether the rows came "
            "from a net or a web scan - only the web class is imported as dynamic."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Holm Security Parser.

        Mirrors the connector's Convert:
        - title: the vulnerability name, then its first CVE, then the Holm id.
        - severity: the severity name, falling back to Holm's numeric level; see severity().
        - description: the detection information, the Holm id, CVEs, URL, port and status.
        - mitigation: Holm's solution text.
        - impact: Holm's own impact statement.
        - references: the vendor reference.
        - cvssv3_score: the CVSS base, falling back to the score.
        - static_finding / dynamic_finding: from the asset class, not the row.
        - unique_id_from_tool: "holm-<hid>[-<asset>][-<port>]".
        - vuln_id_from_tool: the Holm id, which is its rule identity.
        """
        return [
            "title",
            "severity",
            "date",
            "description",
            "mitigation",
            "impact",
            "references",
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
        Return the list of fields used for deduplication in the Holm Security Parser.

        Copied from the Holm Security block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. Note endpoints is among them, so the
        scanned URL is recorded whenever Holm reports one.
        """
        return ["title", "severity", "endpoints", "vuln_id_from_tool"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        rows, asset_class = self.extract(data)
        return [self.build_finding(row, asset_class, test) for row in rows]

    def extract(self, data):
        """
        Return the vulnerabilities and the asset class they came from.

        Holm pages its lists under "results". The class - net or web - is a property of the scan rather
        than the row, so an export states it as a top-level "class" (or "asset_class"). Without it the
        findings are imported as static, which is the connector's own default for anything that is not
        the web class.
        """
        asset_class = ""
        rows = None

        if isinstance(data, list):
            rows = data
        elif isinstance(data, dict):
            for key in ("results", "vulnerabilities"):
                if isinstance(data.get(key), list):
                    rows = data[key]
                    break
            for key in ("class", "asset_class"):
                value = data.get(key)
                if isinstance(value, str) and value.strip():
                    asset_class = value.strip().lower()
                    break

        if rows is None:
            msg = (
                "A Holm Security export is the vulnerabilities response, a JSON object with a "
                f"'results' list; got {type(data).__name__}."
            )
            raise TypeError(msg)
        return [row for row in rows if isinstance(row, dict)], asset_class

    def build_finding(self, row, asset_class, test):
        is_web = asset_class == CLASS_WEB
        cves = [str(cve).strip() for cve in row.get("cve_ids") or [] if str(cve or "").strip()]

        finding = Finding(
            test=test,
            title=self.title(row, cves),
            severity=self.severity(row),
            description=self.describe(row, cves),
            mitigation=str(row.get("solution") or ""),
            impact=str(row.get("vulnerability_impact") or ""),
            references=str(row.get("vendor_reference") or ""),
            unique_id_from_tool=self.unique_id(row),
            vuln_id_from_tool=str(row.get("hid") or "") or None,
            active=self.is_active(row),
            # Only the web class exercises a running application.
            static_finding=not is_web,
            dynamic_finding=is_web,
        )
        finding.cvssv3_score = self.score(row)
        finding.unsaved_tags = self.tags(asset_class)

        if cves:
            finding.unsaved_vulnerability_ids = cves
        if date := self.date(row):
            finding.date = date

        self.attach_endpoint(finding, str(row.get("url") or "").strip())
        return finding

    def unique_id(self, row):
        """
        "holm-<hid>[-<asset>][-<port>]".

        The asset and port are part of the identity because Holm reports the same weakness once per
        host and once per listening port - collapsing them would hide a second exposed service.
        """
        identifier = "holm-" + str(row.get("hid") or "")
        if asset := str(row.get("asset_uuid") or ""):
            identifier += f"-{asset}"
        port = self.flex_int(row.get("detected_port"))
        if port > 0:
            identifier += f"-{port}"
        return identifier

    def title(self, row, cves):
        if name := str(row.get("vulnerability_name") or "").strip():
            return name
        if cves:
            return cves[0]
        return "Holm Security finding " + str(row.get("hid") or "")

    def severity(self, row):
        """
        The severity name wins; Holm's numeric level is the fallback.

        The numeric scale runs 0-4 with 4 the most severe - the inverse of a priority number - and it
        is only consulted when the name is missing or unrecognised, so an unfamiliar name does not
        silently become Info while a usable level sits next to it.
        """
        name = str(row.get("severity") or "").strip().lower()
        if name in SEVERITY_BY_NAME:
            return SEVERITY_BY_NAME[name]
        return SEVERITY_BY_LEVEL.get(self.flex_int(row.get("severity_level")), DEFAULT_SEVERITY)

    def score(self, row):
        """The CVSS base, falling back to the score Holm reports alongside it."""
        for key in ("cvss_base", "cvss_score"):
            value = self.flex_float(row.get(key))
            if value > 0:
                return value
        return 0.0

    def is_active(self, row):
        return str(row.get("status") or "").strip().lower() not in CLOSED_STATUSES

    def describe(self, row, cves):
        lines = []
        for label, value in (("Detection", row.get("detection_information")),
                             ("Holm ID", row.get("hid")),
                             ("CVEs", ", ".join(cves)),
                             ("URL", row.get("url")),
                             ("Port", self.port_label(row)),
                             ("Status", row.get("status"))):
            text = str(value or "").strip()
            if text:
                lines.append(f"**{label}:** {text}")
        return "\n".join(lines)

    def port_label(self, row):
        """"443/tcp" - the port with its protocol when Holm reported one."""
        port = self.flex_int(row.get("detected_port"))
        if port <= 0:
            return ""
        label = str(port)
        if protocol := str(row.get("detected_port_protocol") or "").strip():
            label += f"/{protocol}"
        return label

    def tags(self, asset_class):
        if asset_class == CLASS_WEB:
            return ["web-scan"]
        if asset_class == CLASS_NET:
            return ["net-scan"]
        return []

    def date(self, row):
        """When Holm last saw it, falling back to when it first did."""
        for key in ("last_detected", "first_detected"):
            value = str(row.get(key) or "").strip()
            if len(value) < 10:
                continue
            with suppress(ValueError):
                return datetime.strptime(value[:10], "%Y-%m-%d").date()
        return None

    def attach_endpoint(self, finding, url):
        """
        Record the scanned URL.

        This scan type's deduplication hashes the endpoints, so it is recorded whenever Holm reports
        one - a network finding often has none, and then the host stays in the description.
        """
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
        """
        if HOST_PATTERN.match(value):
            return True
        with suppress(ValueError):
            ip_address(value)
            return True
        return False

    def flex_int(self, value):
        """Holm sends its numbers as either numbers or numeric strings."""
        if isinstance(value, bool) or value is None:
            return 0
        if isinstance(value, int | float):
            return int(value)
        if isinstance(value, str):
            with suppress(ValueError):
                return int(float(value.strip() or 0))
        return 0

    def flex_float(self, value):
        if isinstance(value, bool) or value is None:
            return 0.0
        if isinstance(value, int | float):
            return float(value)
        if isinstance(value, str):
            with suppress(ValueError):
                return float(value.strip() or 0)
        return 0.0
