import json
import re
from contextlib import suppress
from ipaddress import ip_address
from urllib.parse import urlparse

from django.conf import settings

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


class BrightParser:

    """
    Parses a Bright Security scan export.

    Mirrors pkg/tools/bright/converter field for field so a file import and an API sync deduplicate
    against each other instead of producing two copies of everything.

    Bright is a DAST scanner: every issue is an entry point it attacked, which is why this scan type's
    deduplication hash includes the endpoints and the parser always records one.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName.
        return ["Bright - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Bright - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Bright Security scan export (JSON), the issues of one scan. Matches the scan "
            "type used by the Bright connector so file and API findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Bright Parser.

        Mirrors the connector's IssueToFinding:
        - title: the issue name, else "Bright issue <id>".
        - severity: Bright's own label; anything unrecognised is Info.
        - description: the details, the entry point, protocol and CWE, then the request and response
          that proved it.
        - mitigation: Bright's remediation text, when it has one.
        - references: the affected resources, one per line.
        - cvssv3_score / cwe: when Bright reported them.
        - unique_id_from_tool: the issue id.
        """
        return [
            "title",
            "severity",
            "description",
            "mitigation",
            "references",
            "cvssv3_score",
            "cwe",
            "unique_id_from_tool",
            "active",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Bright Parser.

        Copied from the Bright block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. Note endpoints is among them, so the
        entry point must be populated for the hash to mean anything.
        """
        return ["title", "severity", "endpoints"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        return [self.build_finding(issue, test) for issue in self.issues(data)]

    def issues(self, data):
        """
        Return the issues in the export.

        Bright's issues endpoint answers with a bare array, so an export is either that array or an
        object carrying it - a scan with its issues nested.
        """
        if isinstance(data, list):
            return [issue for issue in data if isinstance(issue, dict)]
        if isinstance(data, dict):
            for key in ("issues", "items"):
                if isinstance(data.get(key), list):
                    return [issue for issue in data[key] if isinstance(issue, dict)]
            for key in ("scan", "data"):
                nested = data.get(key)
                if isinstance(nested, dict) and isinstance(nested.get("issues"), list):
                    return [issue for issue in nested["issues"] if isinstance(issue, dict)]

        msg = (
            "A Bright export is a scan's issues, a JSON array or an object with an 'issues' list; got "
            f"{type(data).__name__}."
        )
        raise TypeError(msg)

    def build_finding(self, issue, test):
        identifier = str(issue.get("id") or "")

        finding = Finding(
            test=test,
            title=self.title(issue, identifier),
            severity=self.severity(issue),
            description=self.describe(issue),
            references="\n".join(self.resources(issue)),
            unique_id_from_tool=identifier or None,
            # Bright attacks a running application.
            active=True,
            static_finding=False,
            dynamic_finding=True,
        )

        if remediation := str(issue.get("remediation") or ""):
            finding.mitigation = remediation
        if (score := self.score(issue)) > 0:
            finding.cvssv3_score = score
        if (cwe := self.cwe(issue.get("cwe"))) > 0:
            finding.cwe = cwe

        self.attach_endpoints(finding, issue)
        return finding

    def title(self, issue, identifier):
        if name := str(issue.get("name") or ""):
            return name
        return f"Bright issue {identifier}"

    def severity(self, issue):
        """Bright grades Critical/High/Medium/Low; anything else is Info rather than a guess."""
        label = str(issue.get("severity") or "").strip().lower()
        return SEVERITY_BY_LABEL.get(label, DEFAULT_SEVERITY)

    def describe(self, issue):
        """
        The details, the request context, then the exchange that proved the issue.

        The request and response go in fenced code blocks: they are raw HTTP captured from the target,
        so they must not be read as markup, and a reviewer needs them verbatim to reproduce.
        """
        parts = []
        if details := str(issue.get("details") or ""):
            parts.append(details + "\n\n")

        for label, key in (("Entry Point", "entryPoint"), ("Protocol", "protocol"), ("CWE", "cwe")):
            value = str(issue.get(key) or "")
            if value:
                parts.append(f"**{label}:** {value}\n")

        for label, key in (("Request", "request"), ("Response", "response")):
            value = str(issue.get(key) or "")
            if value:
                parts.append(f"\n**{label}:**\n```\n{value}\n```\n")
        return "".join(parts).rstrip("\n")

    def resources(self, issue):
        rows = issue.get("resources")
        if not isinstance(rows, list):
            return []
        return [str(row).strip() for row in rows if str(row or "").strip()]

    def score(self, issue):
        """Bright sends the CVSS score as either a number or a numeric string."""
        value = issue.get("cvss")
        if isinstance(value, bool) or value is None:
            return 0.0
        if isinstance(value, int | float):
            return float(value)
        if isinstance(value, str):
            with suppress(ValueError):
                return float(value.strip() or 0)
        return 0.0

    def cwe(self, raw):
        """Read a CWE id off "CWE-89" or a bare number; anything else is no CWE."""
        trimmed = str(raw or "").strip().upper().removeprefix("CWE-")
        if not trimmed:
            return 0
        with suppress(ValueError):
            return int(trimmed)
        return 0

    def attach_endpoints(self, finding, issue):
        """
        Record the entry point, falling back to every affected resource.

        This scan type's deduplication hashes the endpoints, so an unpopulated endpoint would leave the
        hash computed over nothing and every rescan would reimport. The fallback is a list because
        Bright reports one issue against several resources when the same weakness is reachable from
        more than one URL.
        """
        entry_point = str(issue.get("entryPoint") or "").strip()
        targets = [entry_point] if entry_point else self.resources(issue)
        for target in targets:
            self.attach_endpoint(finding, target)

    def attach_endpoint(self, finding, url):
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
            if settings.V3_FEATURE_LOCATIONS:
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
        makes Endpoint.clean() raise, and that fails the whole import rather than the one finding. The
        entry point is still in the description.
        """
        if HOST_PATTERN.match(value):
            return True
        with suppress(ValueError):
            ip_address(value)
            return True
        return False
