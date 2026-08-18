import json
import re
from contextlib import suppress
from datetime import date as _date
from ipaddress import ip_address

from dojo.location.feature import locations_enabled
from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

SEVERITY_BY_RATING = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    # Ostorlab's "POTENTIALLY" means a finding it could not fully confirm, which it grades as Low.
    "POTENTIALLY": "Low",
}
# HARDENING, IMPORTANT, INFO and anything unrecognised all land here.
DEFAULT_SEVERITY = "Info"

# A SECURE rating is a check that PASSED, not a finding.
RATING_SECURE = "SECURE"

# Asset types Ostorlab analyses statically - a mobile binary or an uploaded file - as opposed to a
# web, network or domain target it exercises.
STATIC_ASSET_MARKERS = ("ANDROID", "IOS", "APP", "FILE", "STORE")

# The advisory identifiers the connector's shared extractor recognises in free text.
VULNERABILITY_ID_PATTERN = re.compile(
    r"CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|GO-\d{4}-\d+|RHSA-\d{4}:\d+",
)

# The host DefectDojo accepts: letters, digits, dot, hyphen, underscore or plus, at least two
# characters - or an IP address. See Endpoint.clean().
HOST_PATTERN = re.compile(r"^[A-Za-z0-9_\-+][A-Za-z0-9_.\-+]+$")


class OstorlabParser:

    """
    Parses an Ostorlab scan export.

    Mirrors pkg/tools/ostorlab/connector/finding_converter field for field so a file import and an API
    sync deduplicate against each other instead of producing two copies of everything.

    Ostorlab scans mobile applications, web targets and networks from one platform, so whether a
    finding is static or dynamic is decided per scan by its asset type rather than for the tool; see
    is_static(). A SECURE rating is a check that PASSED and is skipped - importing it would file a
    passing check as a finding.

    Ostorlab has no CVE field at all: identifiers appear in the prose and the references, so they are
    extracted from the text; see vulnerability_ids().
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName. Note it does NOT follow the
        # "<Vendor> - Connectors Import" pattern, so it cannot be derived - it has to be copied.
        return ["Ostorlab Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Ostorlab Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import an Ostorlab scan export (JSON) - a scan with its vulnerabilities. Passed (SECURE) "
            "checks are skipped. Matches the scan type used by the Ostorlab connector so file and API "
            "findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Ostorlab Parser.

        Mirrors the connector's Convert:
        - title: the vulnerability detail's title, then "Ostorlab finding <id>".
        - severity: Ostorlab's risk rating; see severity().
        - description: the detail's description and summary, the technical detail, then each
          location metadata entry as its own section.
        - mitigation: the detail's recommendation.
        - cvssv3: the detail's CVSS v3 VECTOR - Ostorlab gives no score.
        - references: each reference as "- <title>: <url>".
        - unsaved_vulnerability_ids: identifiers found in the prose and the references.
        - static_finding / dynamic_finding: decided by the scan's asset type.
        - unique_id_from_tool: "ostorlab-<scan id>-<vulnerability id>".
        """
        return [
            "title",
            "severity",
            "description",
            "mitigation",
            "cvssv3",
            "references",
            "date",
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
        Return the list of fields used for deduplication in the Ostorlab Parser.

        Copied from the Ostorlab block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields.

        Note that neither the connector nor this parser ever sets component_name - Ostorlab reports no
        component - so that third field hashes as empty and the hash is effectively title plus
        severity. Copied as it stands rather than trimmed, because changing it would change how the
        connector's own findings hash; raised in the PR as a follow-up.
        """
        return ["title", "severity", "component_name"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        scan = self.scan(data)
        findings = []
        for row in self.rows(data):
            if self.rating(row).upper() == RATING_SECURE:
                # A SECURE rating is a check that PASSED. Importing it would file a passing check as
                # a finding, which is what the connector's IsIgnored exists to prevent.
                continue
            findings.append(self.build_finding(row, self.block(row, "scan") or scan, test))
        return findings

    def rows(self, data):
        """
        Return the vulnerabilities in the export.

        Ostorlab answers GraphQL: {"data": {"scan": {"vulnerabilities": {"vulnerabilities": [...]}}}}.
        The doubled key is Ostorlab's own shape - the outer one is the connection, the inner one the
        list. Unwrapped forms and a bare array are accepted too.
        """
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]

        if isinstance(data, dict):
            holders = (self.block(self.block(data, "data"), "scan"), self.block(data, "scan"), data)
            for holder in holders:
                connection = holder.get("vulnerabilities")
                if isinstance(connection, dict) and isinstance(
                    connection.get("vulnerabilities"), list,
                ):
                    return [row for row in connection["vulnerabilities"] if isinstance(row, dict)]
                if isinstance(connection, list):
                    return [row for row in connection if isinstance(row, dict)]

        msg = (
            "An Ostorlab export is the vulnerabilities response, a JSON object with a "
            f"'vulnerabilities' list; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def scan(self, data):
        """
        The scan the whole file belongs to - its id, asset type and creation time.

        The scan id is in every identity, and the asset type decides whether the findings are static
        or dynamic, so an export without it loses both. One export is one scan, so it is stated once.
        """
        if not isinstance(data, dict):
            return {}
        for holder in (data, self.block(data, "data")):
            if candidate := self.block(holder, "scan"):
                # The scan object also holds the vulnerabilities connection; that is fine, only its
                # own fields are read.
                return candidate
        return {}

    def block(self, row, key):
        if not isinstance(row, dict):
            return {}
        value = row.get(key)
        return value if isinstance(value, dict) else {}

    def build_finding(self, row, scan, test):
        detail = self.block(row, "detail")
        static = self.is_static(str(scan.get("assetType") or ""))
        title = str(detail.get("title") or "")

        finding = Finding(
            test=test,
            title=title or f"Ostorlab finding {self.integer(row.get('id'))}",
            severity=self.severity(row),
            description=self.describe(row, detail),
            mitigation=str(detail.get("recommendation") or "") or None,
            cvssv3=str(detail.get("cvssV3Vector") or "") or None,
            references=self.references(detail) or None,
            unique_id_from_tool=(
                f"ostorlab-{self.integer(scan.get('id'))}-{self.integer(row.get('id'))}"
            ),
            # Ostorlab scans mobile binaries statically and web or network targets dynamically, so
            # this is decided per scan rather than for the whole tool.
            static_finding=static,
            dynamic_finding=not static,
            active=True,
        )
        finding.unsaved_tags = self.tags(row, scan)

        if title:
            finding.vuln_id_from_tool = title
        if identifiers := self.vulnerability_ids(row, detail):
            finding.unsaved_vulnerability_ids = identifiers
        if date := self.date(scan):
            finding.date = date
        self.add_endpoint(finding, row)
        return finding

    def rating(self, row):
        """Ostorlab's risk rating, which lives on the vulnerability's detail."""
        return str(self.block(row, "detail").get("riskRating") or "").strip()

    def severity(self, row):
        """
        Ostorlab's risk rating.

        "POTENTIALLY" is a finding it could not fully confirm and grades as Low. HARDENING, IMPORTANT
        and INFO all land in Info - which for IMPORTANT reads oddly, and is mirrored rather than
        corrected; see the PR notes.
        """
        return SEVERITY_BY_RATING.get(self.rating(row).upper(), DEFAULT_SEVERITY)

    def is_static(self, asset_type):
        """
        Whether the scan's asset type is analysed without running it.

        A mobile binary, an uploaded file or a store listing is read statically; a web, network or
        domain target is exercised. Matched on substrings because Ostorlab's asset union spells the
        same idea several ways.
        """
        upper = asset_type.upper()
        return any(marker in upper for marker in STATIC_ASSET_MARKERS)

    def describe(self, row, detail):
        """
        Sections, each "**Label:**" then its text, separated by blank lines.

        The location metadata is rendered with ITS OWN type as the label, so a finding carries whatever
        context Ostorlab attached - a URL, a code location, a request - without the parser having to
        know the names in advance.
        """
        sections = []

        def add(label, value):
            if str(value or ""):
                sections.append(f"**{label}:**\n{value}")

        add("Description", detail.get("description"))
        add("Summary", detail.get("shortDescription"))
        add("Technical detail", row.get("technicalDetail"))

        location = self.block(row, "vulnerabilityLocation")
        for meta in location.get("metadata") or []:
            if isinstance(meta, dict) and str(meta.get("metadataType") or ""):
                add(str(meta["metadataType"]), meta.get("metadataValue"))
        return "\n\n".join(sections).strip()

    def references(self, detail):
        """Each reference as "- <title>: <url>", or whichever of the two it has."""
        lines = []
        for reference in detail.get("references") or []:
            if not isinstance(reference, dict):
                continue
            title = str(reference.get("title") or "")
            url = str(reference.get("url") or "")
            if title and url:
                lines.append(f"- {title}: {url}")
            elif url:
                lines.append(f"- {url}")
            elif title:
                lines.append(f"- {title}")
        return "\n".join(lines)

    def vulnerability_ids(self, row, detail):
        """
        Identifiers read out of the prose and the references.

        Ostorlab exposes NO CVE field, so a finding that names one names it in its text. The
        connector's shared extractor sorts its results and drops case-insensitive duplicates, so the
        order here is alphabetical rather than the order they appear in.
        """
        sources = [str(row.get("technicalDetail") or "")]
        sources.extend(
            str(detail.get(key) or "") for key in ("title", "description", "shortDescription")
        )
        for reference in detail.get("references") or []:
            if isinstance(reference, dict):
                sources.extend([str(reference.get("title") or ""), str(reference.get("url") or "")])

        matches = sorted(VULNERABILITY_ID_PATTERN.findall("|".join(sources)))
        identifiers = []
        for match in matches:
            # Adjacent-only dedupe after the sort, which is what slices.CompactFunc does.
            if not identifiers or identifiers[-1].lower() != match.lower():
                identifiers.append(match)
        return identifiers

    def tags(self, row, scan):
        """The risk rating and the scan's asset type."""
        tags = []
        if rating := self.rating(row):
            tags.append(rating)
        if asset_type := str(scan.get("assetType") or ""):
            tags.append(asset_type)
        return tags

    def date(self, scan):
        """The scan's creation time, which the connector parses strictly as RFC 3339."""
        value = str(scan.get("createdTime") or "").strip()
        if not value:
            return None
        with suppress(ValueError):
            return _date.fromisoformat(value.split("T")[0])
        return None

    def add_endpoint(self, finding, row):
        """
        The affected host, for a web or network target.

        Ostorlab names it either way round, so the asset's name is tried before its host. A mobile
        scan has neither, and then there is no endpoint to record.
        """
        asset = self.block(self.block(row, "vulnerabilityLocation"), "asset")
        for key in ("name", "host"):
            host = str(asset.get(key) or "").strip()
            if not host:
                continue
            if not self.usable_host(host):
                # A host DefectDojo rejects makes Endpoint.clean() raise, and that fails the WHOLE
                # import rather than the one finding.
                return
            if locations_enabled():
                finding.unsaved_locations.append(LocationData.url(host=host))
            else:
                # TODO: Delete this after the move to Locations
                finding.unsaved_endpoints.append(Endpoint(host=host))
            return

    def usable_host(self, value):
        """A host is letters, digits, dot, hyphen, underscore or plus, or an IP address."""
        if HOST_PATTERN.match(value):
            return True
        with suppress(ValueError):
            ip_address(value)
            return True
        return False

    def integer(self, value):
        """Ostorlab's ids may arrive as JSON numbers or quoted strings."""
        if isinstance(value, bool) or value is None:
            return 0
        if isinstance(value, int | float):
            return int(value)
        if isinstance(value, str):
            with suppress(ValueError):
                return int(float(value.strip() or 0))
        return 0
