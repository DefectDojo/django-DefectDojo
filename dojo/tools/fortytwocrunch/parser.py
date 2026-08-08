import json
import re
from contextlib import suppress
from ipaddress import ip_address
from urllib.parse import urlparse

from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

# 42Crunch grades both audit and scan issues on one integer scale, 1 = info and 5 = critical.
SEVERITY_BY_CRITICALITY = {5: "Critical", 4: "High", 3: "Medium", 2: "Low"}
DEFAULT_SEVERITY = "Info"

# The audit sections, in the connector's own order, with the category label each one carries.
AUDIT_CATEGORIES = (
    ("security", "security"),
    ("data", "data-validation"),
    ("warnings", "warning"),
    ("semanticErrors", "semantic-error"),
    ("validationErrors", "validation-error"),
)

TOOL_TAG = "42crunch"
TITLE_MAX_LENGTH = 250

# The host DefectDojo accepts: letters, digits, dot, hyphen, underscore or plus, at least two
# characters - or an IP address. See Endpoint.clean().
HOST_PATTERN = re.compile(r"^[A-Za-z0-9_\-+][A-Za-z0-9_.\-+]+$")


class FortytwocrunchParser:

    """
    Parses a 42Crunch Security Audit or Conformance Scan report.

    Mirrors pkg/tools/fortytwocrunch/connector/converter field for field so a file import and an API
    sync deduplicate against each other instead of producing two copies of everything.

    42Crunch produces two different reports for one API and the connector converts both under a single
    scan type: an audit of the OpenAPI definition (static) and a conformance scan of the running API
    (dynamic). This parser accepts either, deciding by shape; see get_findings().

    Both reports store their strings in INDEX TABLES and refer to them by integer, so a description or
    a location has to be looked up rather than read - a finding built from the integers alone would
    carry no text at all. See audit_pointer(), scan_description() and scan_pointer().
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName.
        return ["42Crunch - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "42Crunch - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a 42Crunch Security Audit report (static, of the OpenAPI definition) or "
            "Conformance Scan report (dynamic, of the running API). Matches the scan type used by the "
            "42Crunch connector so file and API findings deduplicate - give the report's apiId to "
            "deduplicate against connector findings."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the 42Crunch Parser.

        Mirrors the connector's ConvertAuditReport and ConvertScanReport:
        - title: the issue description, then the specific one, then the issue id (audit); the resolved
          injection description, then the operation (scan). Truncated to 250 characters.
        - severity: 42Crunch's criticality integer, where 5 is the most severe.
        - description: the prose, then the category and OpenAPI location (audit); the operation, URL,
          response status and OpenAPI location (scan).
        - file_path: the JSON Pointer into the OpenAPI definition (audit only).
        - steps_to_reproduce: 42Crunch's own curl command (scan only).
        - static_finding / dynamic_finding: an audit is static, a scan is dynamic.
        - unique_id_from_tool: "<api id>/audit/<issue id>/<pointer>" or
          "<api id>/scan/<METHOD> <path>/<check index>".
        """
        return [
            "title",
            "severity",
            "description",
            "file_path",
            "steps_to_reproduce",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "tags",
            "active",
            "static_finding",
            "dynamic_finding",
        ]

    # No get_dedupe_fields: this scan type has no curated hash-field list, so it deduplicates with
    # DefectDojo's default algorithm - which is exactly what the connector's own findings do today.
    # Choosing hash fields here would also change how those findings deduplicate.

    def get_findings(self, filename, test):
        data = json.load(filename)
        if not isinstance(data, dict):
            msg = (
                "A 42Crunch report is a JSON object - a Security Audit report or a Conformance Scan "
                f"report; got {type(data).__name__}."
            )
            raise TypeError(msg)

        api_id, report = self.unwrap(data)

        if self.is_scan_report(report):
            return self.scan_findings(api_id, report, test)
        if self.is_audit_report(report):
            return self.audit_findings(api_id, report, test)

        msg = (
            "This is neither a 42Crunch Security Audit report (an 'index' table with 'security', "
            "'data' or 'warnings' sections) nor a Conformance Scan report (a 'data.paths' object)."
        )
        raise TypeError(msg)

    def unwrap(self, data):
        """
        Return the API id and the report itself.

        The API id is part of every identity the connector builds, and a downloaded report does not
        carry it - so it is read from the file when a wrapper states it. WITHOUT it the identities
        differ from the connector's and file findings will not deduplicate against synced ones, which
        is why the docs ask for it.
        """
        api_id = ""
        for key in ("apiId", "api_id", "apiID"):
            if value := str(data.get(key) or "").strip():
                api_id = value
                break

        report = data
        for key in ("report", "audit", "scan"):
            if isinstance(data.get(key), dict):
                report = data[key]
                break
        return api_id, report

    def is_audit_report(self, report):
        return isinstance(report.get("index"), list) or any(
            isinstance(report.get(key), dict) for key, _ in AUDIT_CATEGORIES
        )

    def is_scan_report(self, report):
        """A scan report is recognised by its per-path/method issue tree."""
        return bool(self.block(self.block(report, "data"), "paths"))

    def block(self, row, key):
        if not isinstance(row, dict):
            return {}
        value = row.get(key)
        return value if isinstance(value, dict) else {}

    # --- Security Audit report (static) ---

    def audit_findings(self, api_id, report, test):
        index = [str(entry) for entry in report.get("index") or []]
        findings = []
        for key, category in AUDIT_CATEGORIES:
            issues = self.block(self.block(report, key), "issues")
            for issue_id, group in issues.items():
                if not isinstance(group, dict):
                    continue
                occurrences = group.get("issues")
                if not isinstance(occurrences, list):
                    continue
                findings.extend(
                    self.audit_finding(api_id, category, str(issue_id), group, occurrence, index, test)
                    for occurrence in occurrences
                    if isinstance(occurrence, dict)
                )
        return findings

    def audit_finding(self, api_id, category, issue_id, group, occurrence, index, test):
        pointer = self.audit_pointer(occurrence, index)
        description = str(group.get("description") or "")
        specific = str(occurrence.get("specificDescription") or "")

        identifier = f"{api_id}/audit/{issue_id}/"
        if pointer:
            identifier += pointer
        else:
            # No resolvable location, so the raw pointer index keeps two occurrences of one issue
            # apart. Without it they would collapse into a single finding.
            identifier += f"#{self.integer(occurrence.get('pointer'))}"

        finding = Finding(
            test=test,
            title=self.truncate(self.first(description, specific, issue_id)),
            severity=self.severity(group.get("criticality")),
            description=self.audit_description(specific, description, category, pointer),
            file_path=pointer or None,
            unique_id_from_tool=identifier,
            vuln_id_from_tool=issue_id,
            # An audit reads the OpenAPI definition; nothing is exercised.
            static_finding=True,
            dynamic_finding=False,
            active=True,
        )
        finding.unsaved_tags = [TOOL_TAG, "audit", category]
        return finding

    def audit_pointer(self, occurrence, index):
        """
        Resolve an occurrence's integer pointer against the report's index table.

        An out-of-range index resolves to nothing rather than raising: the report is still importable,
        and the finding keeps its identity through the raw index instead.
        """
        position = self.integer(occurrence.get("pointer"))
        if 0 <= position < len(index):
            return index[position]
        return ""

    def audit_description(self, specific, description, category, pointer):
        parts = []
        if paragraph := self.first(specific, description):
            parts.append(f"{paragraph}\n\n")
        for prefix, value in (("Category:", category), ("OpenAPI location:", pointer)):
            if str(value or "").strip():
                parts.append(f"* **{prefix}** {value}\n")
        return "".join(parts)

    # --- Conformance Scan report (dynamic) ---

    def scan_findings(self, api_id, report, test):
        data = self.block(report, "data")
        index = self.block(data, "index")
        pointers = [str(entry) for entry in index.get("jsonPointers") or []]
        templates = [str(entry) for entry in index.get("injectionDescriptions") or []]

        findings = []
        for path, methods in self.block(data, "paths").items():
            if not isinstance(methods, dict):
                continue
            for method, holder in methods.items():
                issues = holder.get("issues") if isinstance(holder, dict) else None
                if not isinstance(issues, list):
                    continue
                findings.extend(
                    self.scan_finding(api_id, str(path), str(method), issue, pointers, templates, test)
                    for issue in issues
                    if isinstance(issue, dict)
                )
        return findings

    def scan_finding(self, api_id, path, method, issue, pointers, templates, test):
        operation = f"{method.upper()} {path}"
        description = self.scan_description(issue, templates)
        check = self.integer(issue.get("injectionDescription"))

        # The scan issue's own id is a per-scan UUID, so it is NOT stable across scans. The identity
        # uses the operation plus the check index instead, which is the same for the same issue.
        finding = Finding(
            test=test,
            title=self.truncate(self.first(description, operation)),
            severity=self.severity(issue.get("criticality")),
            description=self.scan_description_block(issue, description, operation, pointers),
            steps_to_reproduce=str(issue.get("curl") or "") or None,
            unique_id_from_tool=f"{api_id}/scan/{operation}/{check}",
            # A conformance scan exercises the running API.
            static_finding=False,
            dynamic_finding=True,
            active=True,
        )
        finding.unsaved_tags = [TOOL_TAG, "scan", method.upper()]
        self.add_endpoint(finding, str(issue.get("url") or ""))
        return finding

    def scan_description(self, issue, templates):
        """
        Resolve the issue's injection-description template and substitute its parameters.

        The template is referenced by integer and its parameters are a separate list, so each "%s" is
        filled in turn - one substitution per parameter, as the connector does. Reading the integer
        alone would leave the finding with no description.
        """
        position = self.integer(issue.get("injectionDescription"))
        if not (0 <= position < len(templates)):
            return ""

        result = templates[position]
        for param in issue.get("injectionDescriptionParams") or []:
            result = result.replace("%s", str(param), 1)
        return result

    def scan_description_block(self, issue, description, operation, pointers):
        parts = []
        if description.strip():
            parts.append(f"{description}\n\n")
        for prefix, value in (("Operation:", operation), ("URL:", str(issue.get("url") or ""))):
            if str(value or "").strip():
                parts.append(f"* **{prefix}** {value}\n")

        if (status := self.integer(issue.get("responseHttpStatusCode"))) != 0:
            parts.append(f"* **Response status:** {status}\n")
        if pointer := self.scan_pointer(issue, pointers):
            parts.append(f"* **OpenAPI location:** {pointer}\n")
        return "".join(parts)

    def scan_pointer(self, issue, pointers):
        position = self.integer(issue.get("jsonPointer"))
        if 0 <= position < len(pointers):
            return pointers[position]
        return ""

    def add_endpoint(self, finding, raw_url):
        """
        The endpoint is the URL's ORIGIN only - scheme and host, no path.

        That is what the connector records: a conformance scan hits many paths on one host, and the
        operation is already in the description and the identity.
        """
        if not raw_url:
            return
        with suppress(ValueError):
            parsed = urlparse(raw_url)
            host = parsed.hostname or ""
            if not parsed.scheme or not host or not self.usable_host(host):
                return
            if settings.V3_FEATURE_LOCATIONS:
                finding.unsaved_locations.append(
                    LocationData.url(host=host, protocol=parsed.scheme, port=parsed.port),
                )
            else:
                # TODO: Delete this after the move to Locations
                finding.unsaved_endpoints.append(
                    Endpoint(host=host, protocol=parsed.scheme, port=parsed.port),
                )

    def usable_host(self, value):
        """
        Whether DefectDojo will accept this as an endpoint host.

        A host is letters, digits, dot, hyphen, underscore or plus, or an IP address. Anything else
        makes Endpoint.clean() raise, and that fails the WHOLE import rather than the one finding.
        The URL is still in the description either way.
        """
        if HOST_PATTERN.match(value):
            return True
        with suppress(ValueError):
            ip_address(value)
            return True
        return False

    # --- shared ---

    def severity(self, criticality):
        """
        42Crunch's criticality integer, where 5 is the most severe.

        This is the inverse of nothing - it is its own scale - but 1 means informational, so reading a
        low number as a low severity is right here and wrong for a scanner that grades 1 as critical.
        Zero and out-of-range values are Info.
        """
        return SEVERITY_BY_CRITICALITY.get(self.integer(criticality), DEFAULT_SEVERITY)

    def truncate(self, value):
        """At most 250 characters, ending in an ellipsis when it is cut, as the connector does."""
        if len(value) <= TITLE_MAX_LENGTH:
            return value
        return value[: TITLE_MAX_LENGTH - 3] + "..."

    def first(self, *values):
        """
        The first value that is not the empty string.

        The connector does NOT trim before testing, so a value that is only whitespace counts as
        present - which a plain truthiness test reproduces exactly, since "" is falsy and " " is not.
        """
        for value in values:
            if value:
                return value
        return ""

    def integer(self, value):
        if isinstance(value, bool) or value is None:
            return 0
        if isinstance(value, int | float):
            return int(value)
        if isinstance(value, str):
            with suppress(ValueError):
                return int(float(value.strip() or 0))
        return 0
