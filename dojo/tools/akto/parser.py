import json
import re
from contextlib import suppress
from datetime import UTC, datetime
from ipaddress import ip_address
from urllib.parse import urlparse

from dojo.location.feature import locations_enabled
from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

SEVERITY_BY_LABEL = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
}
DEFAULT_SEVERITY = "Info"

# Akto's issue statuses. IGNORED is how a reviewer marks a false positive; FIXED means it is gone.
STATUS_FIXED = "FIXED"
STATUS_IGNORED = "IGNORED"

# The advisory identifiers the connector's shared extractor recognises.
VULNERABILITY_ID_PATTERN = re.compile(
    r"CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|GO-\d{4}-\d+|RHSA-\d{4}:\d+",
)

# The host DefectDojo accepts: letters, digits, dot, hyphen, underscore or plus, at least two
# characters - or an IP address. See Endpoint.clean().
HOST_PATTERN = re.compile(r"^[A-Za-z0-9_\-+][A-Za-z0-9_.\-+]+$")


class AktoParser:

    """
    Parses an Akto API-security export.

    Mirrors pkg/tools/akto/connector/finding_converter field for field so a file import and an API sync
    deduplicate against each other instead of producing two copies of everything.

    Akto tests API endpoints, so a finding is a test run against one method and path. The endpoint is
    part of both the identity and the deduplication hash, and it doubles as the component - which is
    why component_name is "<METHOD> <url>" rather than a package name.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName. Note it does NOT follow the
        # "<Vendor> - Connectors Import" pattern, so it cannot be derived - it has to be copied.
        return ["Akto Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Akto Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import an Akto API-security export (JSON), the fetchIssuesFromCollections response. "
            "Matches the scan type used by the Akto connector so file and API findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Akto Parser.

        Mirrors the connector's Convert:
        - title: the test name, then its sub-category, then a constant.
        - severity: Akto's own label, matched case-insensitively; anything unrecognised is Info.
        - description: the endpoint, then Akto's description, impact and details.
        - mitigation: Akto's remediation text.
        - component_name: "<METHOD> <url>" - the tested endpoint, which is what Akto reports against.
        - cwe: parsed from "CWE-89" or a bare number.
        - active / false_p: from the issue status; see status().
        - unique_id_from_tool: "akto-<collection>-<method>-<url>-<test sub-category>".
        - vuln_id_from_tool: the test sub-category, which is Akto's rule identity.
        """
        return [
            "title",
            "severity",
            "date",
            "description",
            "mitigation",
            "references",
            "component_name",
            "cwe",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "unsaved_vulnerability_ids",
            "tags",
            "active",
            "false_p",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Akto Parser.

        Copied from the Akto block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. Both the endpoint and the test are in
        the hash: the same test against two paths is two findings, and two different tests against one
        path are as well.
        """
        return ["title", "severity", "endpoints", "vuln_id_from_tool"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        return [self.build_finding(issue, test) for issue in self.issues(data)]

    def issues(self, data):
        """
        Return the issues in the export.

        Akto's issues endpoint nests them under "issueDetails"; a bare array is accepted too.
        """
        if isinstance(data, list):
            return [issue for issue in data if isinstance(issue, dict)]
        if isinstance(data, dict):
            for key in ("issueDetails", "issues"):
                if isinstance(data.get(key), list):
                    return [issue for issue in data[key] if isinstance(issue, dict)]

        msg = (
            "An Akto export is the issues response, a JSON object with an 'issueDetails' list; got "
            f"{type(data).__name__}."
        )
        raise TypeError(msg)

    def build_finding(self, issue, test):
        component = self.component_name(issue)
        active, false_positive = self.status(issue)

        finding = Finding(
            test=test,
            title=self.title(issue),
            severity=self.severity(issue),
            description=self.describe(issue, component),
            mitigation=str(issue.get("testRemediation") or ""),
            references=self.references(issue),
            component_name=component or None,
            cwe=self.cwe(issue.get("testCwe")),
            unique_id_from_tool=self.unique_id(issue),
            vuln_id_from_tool=str(issue.get("testSubCategory") or "") or None,
            active=active,
            false_p=false_positive,
            # Akto exercises a running API.
            static_finding=False,
            dynamic_finding=True,
        )
        finding.unsaved_tags = self.tags(issue)

        if identifiers := self.vulnerability_ids(issue):
            finding.unsaved_vulnerability_ids = identifiers
        if date := self.date(issue):
            finding.date = date

        self.attach_endpoint(finding, issue)
        return finding

    def unique_id(self, issue):
        """
        "akto-<collection>-<method>-<url>-<test sub-category>".

        The path and the test are both in the identity because Akto runs every test against every
        endpoint it knows: neither alone identifies a finding.
        """
        return "-".join([
            "akto",
            str(self.flex_int(issue.get("apiCollectionId"))),
            str(issue.get("apiMethod") or ""),
            str(issue.get("apiUrl") or ""),
            str(issue.get("testSubCategory") or ""),
        ])

    def title(self, issue):
        for key in ("testName", "testSubCategory"):
            if value := str(issue.get(key) or ""):
                return value
        return "Akto API-security issue"

    def severity(self, issue):
        label = str(issue.get("severity") or "").strip().upper()
        return SEVERITY_BY_LABEL.get(label, DEFAULT_SEVERITY)

    def status(self, issue):
        """
        Akto records triage in the status: IGNORED is a false positive, FIXED is gone.

        Both are inactive; only IGNORED sets the false-positive flag, because "fixed" is not a
        judgement about whether the finding was real.
        """
        status = str(issue.get("status") or "").strip().upper()
        return status not in {STATUS_FIXED, STATUS_IGNORED}, status == STATUS_IGNORED

    def component_name(self, issue):
        """
        "<METHOD> <url>" - the tested endpoint.

        Akto has no package to report, so the endpoint is the component, and that is what the
        deduplication hash's component slot means for this scan type.
        """
        method = str(issue.get("apiMethod") or "").strip()
        url = str(issue.get("apiUrl") or "").strip()
        if method and url:
            return f"{method} {url}"
        return url

    def describe(self, issue, component):
        lines = []
        for label, value in (("Endpoint", component),
                             ("Description", issue.get("testDescription")),
                             ("Impact", issue.get("testImpact")),
                             ("Details", issue.get("testDetails"))):
            text = str(value or "").strip()
            if text:
                lines.append(f"**{label}:** {text}")
        return "\n".join(lines)

    def references(self, issue):
        """Akto's own issue link, then the test's reference links."""
        links = []
        if url := str(issue.get("issueUrl") or "").strip():
            links.append(url)
        for reference in issue.get("testReferences") or []:
            text = str(reference or "").strip()
            if text:
                links.append(text)
        return "\n".join(links)

    def tags(self, issue):
        tags = []
        if category := str(issue.get("testCategory") or "").strip():
            tags.append(category)
        for tag in issue.get("testTags") or []:
            text = str(tag or "").strip()
            if text:
                tags.append(text)
        return tags

    def cwe(self, raw):
        """Read a CWE id off "CWE-89" or a bare number; anything else is no CWE."""
        trimmed = str(raw or "").strip().upper().removeprefix("CWE-")
        with suppress(ValueError):
            return int(trimmed)
        return 0

    def vulnerability_ids(self, issue):
        """
        Identifiers in Akto's CVE field, sorted and deduplicated case-insensitively.

        That is the shared extractor's behaviour, and the field is free text - an API-security test
        usually has no CVE at all, but a dependency-related one may name several.
        """
        found = sorted(VULNERABILITY_ID_PATTERN.findall(str(issue.get("testCve") or "")))
        identifiers = []
        for candidate in found:
            if not identifiers or identifiers[-1].lower() != candidate.lower():
                identifiers.append(candidate)
        return identifiers

    def date(self, issue):
        """Akto timestamps in unix seconds."""
        value = self.flex_int(issue.get("creationTime"))
        if value <= 0:
            return None
        with suppress(OSError, OverflowError, ValueError):
            return datetime.fromtimestamp(value, tz=UTC).date()
        return None

    def attach_endpoint(self, finding, issue):
        """
        Record the tested URL, but only when Akto reported an absolute one.

        Akto's apiUrl is often just a path - "/api/v1/users" - which is not an endpoint on its own, and
        the connector deliberately skips those rather than inventing a host. The path is still the
        component and appears in the description, so nothing is lost.
        """
        url = str(issue.get("apiUrl") or "").strip()
        if not url.startswith(("http://", "https://")):
            return
        with suppress(ValueError):
            parsed = urlparse(url)
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
        """Akto sends its ids and timestamps as either numbers or numeric strings."""
        if isinstance(value, bool) or value is None:
            return 0
        if isinstance(value, int | float):
            return int(value)
        if isinstance(value, str):
            with suppress(ValueError):
                return int(value.strip() or 0)
        return 0
