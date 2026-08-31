import json
import re
from contextlib import suppress
from ipaddress import ip_address
from urllib.parse import urlparse

from dojo.location.feature import locations_enabled
from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

SEVERITY_BY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
DEFAULT_SEVERITY = "Info"

# The host DefectDojo accepts: letters, digits, dot, hyphen, underscore or plus, at least two
# characters - or an IP address. See Endpoint.clean().
HOST_PATTERN = re.compile(r"^[A-Za-z0-9_\-+][A-Za-z0-9_.\-+]+$")


class EscapeParser:

    """
    Parses an Escape API-security scan export.

    Mirrors pkg/tools/escape/converter field for field so a file import and an API sync deduplicate
    against each other instead of producing two copies of everything.

    Escape scans an API rather than a site: every issue is a method and a URL, which is why this scan
    type's deduplication hash includes the endpoints and the parser always records the tested URL.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName.
        return ["Escape - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Escape - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import an Escape scan export (JSON), the issues of an application's latest scan. Matches "
            "the scan type used by the Escape connector so file and API findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Escape Parser.

        Mirrors the connector's IssueToFinding:
        - title: the issue name, else "Escape issue <id>".
        - severity: Escape's own label; anything unrecognised is Info.
        - description: the issue prose, then the method and URL, the OWASP category and the CWE.
        - mitigation: Escape's remediation text, when it has one.
        - cwe: parsed from "CWE-89" or a bare number.
        - unique_id_from_tool: the issue id.
        """
        return [
            "title",
            "severity",
            "description",
            "mitigation",
            "cwe",
            "unique_id_from_tool",
            "tags",
            "active",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Escape Parser.

        Copied from the Escape block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. Note endpoints is among them, so the
        tested URL must be populated for the hash to mean anything.
        """
        return ["title", "severity", "endpoints"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        return [self.build_finding(issue, test) for issue in self.issues(data)]

    def issues(self, data):
        """
        Return the issues in the export.

        Escape nests them under the scan that produced them - the connector reads an application's
        latest scan - so an export is a scan object, an application carrying one, or the issue list
        itself.
        """
        if isinstance(data, list):
            return [issue for issue in data if isinstance(issue, dict)]
        if isinstance(data, dict):
            if isinstance(data.get("issues"), list):
                return [issue for issue in data["issues"] if isinstance(issue, dict)]
            for key in ("lastScan", "scan"):
                nested = data.get(key)
                if isinstance(nested, dict) and isinstance(nested.get("issues"), list):
                    return [issue for issue in nested["issues"] if isinstance(issue, dict)]
            # An applications response: take the issues of every application's latest scan.
            applications = data.get("applications")
            if isinstance(applications, list):
                collected = []
                for application in applications:
                    if not isinstance(application, dict):
                        continue
                    scan = application.get("lastScan")
                    if isinstance(scan, dict) and isinstance(scan.get("issues"), list):
                        collected.extend(issue for issue in scan["issues"] if isinstance(issue, dict))
                return collected

        msg = (
            "An Escape export is a scan, a JSON object with an 'issues' list; got "
            f"{type(data).__name__}."
        )
        raise TypeError(msg)

    def build_finding(self, issue, test):
        identifier = str(issue.get("id") or "").strip()

        finding = Finding(
            test=test,
            title=self.title(issue, identifier),
            severity=self.severity(issue),
            description=self.describe(issue),
            unique_id_from_tool=identifier or None,
            # Escape exercises a running API.
            active=True,
            static_finding=False,
            dynamic_finding=True,
        )
        finding.unsaved_tags = self.tags(issue)

        if remediation := str(issue.get("remediation") or "").strip():
            finding.mitigation = remediation
        if (cwe := self.cwe(issue.get("cwe"))) > 0:
            finding.cwe = cwe

        self.attach_endpoint(finding, str(issue.get("url") or "").strip())
        return finding

    def title(self, issue, identifier):
        if name := str(issue.get("name") or "").strip():
            return name
        return f"Escape issue {identifier}"

    def severity(self, issue):
        """
        Escape's own label.

        It rates by OWASP category and severity word - high/medium/low/info - and an unrecognised
        label is Info rather than a guess.
        """
        label = str(issue.get("severity") or "").strip().lower()
        return SEVERITY_BY_LABEL.get(label, DEFAULT_SEVERITY)

    def describe(self, issue):
        """
        The issue prose, then the endpoint, OWASP category and CWE.

        The endpoint line carries the method when Escape reported one - "GET https://..." - because
        the same URL behaves differently per verb, which is the point of an API scanner.
        """
        parts = []
        if description := str(issue.get("description") or "").strip():
            parts.append(description + "\n\n")

        method = str(issue.get("method") or "").strip()
        url = str(issue.get("url") or "").strip()
        if method and url:
            parts.append(f"**Endpoint:** {method} {url}\n")
        elif url:
            parts.append(f"**Endpoint:** {url}\n")

        for label, value in (("OWASP", issue.get("owasp")), ("CWE", issue.get("cwe"))):
            text = str(value or "").strip()
            if text:
                parts.append(f"**{label}:** {text}\n")
        return "".join(parts).rstrip("\n")

    def tags(self, issue):
        tags = []
        if owasp := str(issue.get("owasp") or "").strip():
            tags.append(f"owasp:{owasp}")
        if method := str(issue.get("method") or "").strip():
            tags.append(f"method:{method.upper()}")
        return tags

    def cwe(self, raw):
        """Read a CWE id off "CWE-89" or a bare number; anything else is no CWE."""
        trimmed = str(raw or "").strip().upper().removeprefix("CWE-")
        if not trimmed:
            return 0
        with suppress(ValueError):
            return int(trimmed)
        return 0

    def attach_endpoint(self, finding, url):
        """
        Record the tested URL.

        This scan type's deduplication hashes the endpoints, so an unpopulated endpoint would leave
        the hash computed over nothing and every rescan would reimport.
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
        The URL is still in the description.
        """
        if HOST_PATTERN.match(value):
            return True
        with suppress(ValueError):
            ip_address(value)
            return True
        return False
