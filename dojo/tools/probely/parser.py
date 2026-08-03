import json
import re
from contextlib import suppress
from ipaddress import ip_address
from urllib.parse import urlparse

from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

# Probely reports severity as an integer, and only these three values exist. Anything else becomes
# Info, which is what the connector does after logging it.
SEVERITY_MAP = {
    10: "Low",
    20: "Medium",
    30: "High",
}
DEFAULT_SEVERITY = "Info"

# States the connector treats as not worth importing. "retesting" is deliberately NOT here: a
# finding being re-tested is assumed still open and still being worked on.
IGNORED_STATES = frozenset({"invalid", "accepted", "fixed"})

# Insertion-point words that should not be title-cased naively.
ACRONYMS = (("Url", "URL"), ("Json", "JSON"), ("Graphql", "GraphQL"))


# The host DefectDojo accepts: letters, digits, dot, hyphen, underscore or plus, at least two
# characters - or an IP address. See Endpoint.clean().
HOST_PATTERN = re.compile(r"^[A-Za-z0-9_\-+][A-Za-z0-9_.\-+]+$")


class ProbelyParser:

    """
    Parses a Probely findings export.

    Mirrors pkg/tools/probely/connector/finding_converter.go field for field so a file import and an
    API sync deduplicate against each other instead of producing two copies of everything.

    Probely is a DAST scanner, so every finding is dynamic and carries the scanned URL. Note the
    deduplication configuration for this scan type hashes the ENDPOINTS, so the endpoint has to be
    populated or the hash is computed over nothing.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanType(). Note it does NOT follow the
        # "<Vendor> - Connectors Import" pattern the other connector scan types use.
        return ["Probely API Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Probely API Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Probely findings export (JSON). Matches the scan type used by the Probely "
            "connector so file and API findings deduplicate. Findings Probely records as fixed, "
            "invalid or accepted are not imported."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Probely Parser.

        Mirrors the connector's ConvertFinding:
        - title: the finding definition's name.
        - severity: Probely's integer severity, 10/20/30; anything else Info.
        - severity_justification: the connector's sentence about severity, score and vector.
        - description: path, the insertion point and parameter, method, the definition's
          description, and Probely's evidence.
        - mitigation: Probely's fix text followed by its extra notes.
        - cvssv3 / cvssv3_score: the reported vector and score.
        - cwe: parsed from the finding definition's cwe_id when the export carries one.
        - unique_id_from_tool: the Probely finding id.
        - vuln_id_from_tool: the finding definition's id.
        """
        return [
            "title",
            "severity",
            "severity_justification",
            "description",
            "mitigation",
            "cvssv3",
            "cvssv3_score",
            "cwe",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Probely Parser.

        Copied from the Probely block in the Pro connector settings. Note it pairs the plain
        hash_code algorithm with a wide field set that includes endpoints, so the endpoint must be
        populated for the hash to mean anything.
        """
        return [
            "title",
            "description",
            "severity",
            "vuln_id_from_tool",
            "unique_id_from_tool",
            "endpoints",
            "cwe",
            "mitigation",
        ]

    def get_findings(self, filename, test):
        data = json.load(filename)
        rows = self.extract_rows(data)

        findings = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            if self.is_ignored(row):
                continue
            finding = self.build_finding(row, test)
            findings.setdefault(finding.unique_id_from_tool, finding)
        return list(findings.values())

    def extract_rows(self, data):
        """Probely's findings endpoint pages the results under "results"."""
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and isinstance(data.get("results"), list):
            return data["results"]
        msg = (
            "A Probely export is a JSON object with a 'results' list of findings, or a bare array "
            f"of findings; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def is_ignored(self, row):
        """
        Skip findings Probely has closed out.

        A finding being re-tested is NOT skipped: the connector assumes a re-test means the issue is
        still open and being worked on, and importing it is the safe side of that assumption.
        """
        return (row.get("state") or "").strip().lower() in IGNORED_STATES

    def build_finding(self, row, test):
        definition = row.get("definition") or {}
        score = row.get("cvss_score") or 0
        severity = self.severity(row)

        finding = Finding(
            test=test,
            title=definition.get("name") or None,
            severity=severity,
            severity_justification=self.justification(severity, score, row.get("cvss_vector")),
            description=self.describe(row, definition),
            mitigation=f"{row.get('fix') or ''}\n{row.get('extra') or ''}",
            cvssv3=row.get("cvss_vector") or None,
            cvssv3_score=score or None,
            cwe=self.cwe(definition),
            unique_id_from_tool=str(row.get("id")),
            vuln_id_from_tool=definition.get("id") or None,
            # Probely is DAST: it probes a running target.
            static_finding=False,
            dynamic_finding=True,
        )
        self.attach_endpoint(finding, row.get("url"))
        return finding

    def attach_endpoint(self, finding, url):
        """
        Record the scanned origin.

        The connector reduces the finding URL to scheme and host. That matters here beyond tidiness:
        this scan type's deduplication hashes the endpoints, so an unpopulated endpoint would leave
        the hash computed over nothing.
        """
        if not url:
            return
        with suppress(ValueError):
            parsed = urlparse(url)
            if not parsed.hostname or not self.usable_host(parsed.hostname):
                return
            if settings.V3_FEATURE_LOCATIONS:
                finding.unsaved_locations.append(LocationData.url(
                    host=parsed.hostname, protocol=parsed.scheme or None, port=parsed.port,
                ))
            else:
                # TODO: Delete this after the move to Locations
                finding.unsaved_endpoints.append(Endpoint(
                    host=parsed.hostname, protocol=parsed.scheme or None, port=parsed.port,
                ))

    def usable_host(self, value):
        """
        Whether DefectDojo will accept this as an endpoint host.

        A host is letters, digits, dot, hyphen, underscore or plus, or an IP address. Anything else -
        a path, a space, a container image tag - makes Endpoint.clean() raise, and that fails the
        whole import rather than the one finding, so it is dropped here instead. The value is still
        reported in the description, so nothing is lost.
        """
        if HOST_PATTERN.match(value):
            return True
        with suppress(ValueError):
            ip_address(value)
            return True
        return False

    def severity(self, row):
        raw = row.get("severity")
        with suppress(TypeError, ValueError):
            return SEVERITY_MAP.get(int(raw), DEFAULT_SEVERITY)
        return DEFAULT_SEVERITY

    def justification(self, severity, score, vector):
        """The connector's sentence, including its one-decimal score and italicised vector."""
        return (
            f"Probely has issued a severity level of **{severity}** from a base CVSS score of "
            f"**{score:.1f}**.\n*{vector or ''}*"
        )

    def describe(self, row, definition):
        description = f"**Path:** {row.get('path') or ''}\n"
        description += self.parameter_info(row)
        if row.get("method"):
            description += f"**Method:** {row['method'].upper()}\n"
        # Probely names this field "desc", not "description".
        description += f"**Description:** \n{definition.get('desc') or ''}\n\n"
        description += f"**Evidence:** \n{row.get('evidence') or ''}"
        return description

    def parameter_info(self, row):
        """
        Render the insertion point as a label, e.g. "url_path" becomes "**URL Path:**".

        The acronym fixes are the connector's: naive title casing would produce "Url" and "Json".
        """
        insertion_point = row.get("insertion_point") or ""
        if not insertion_point:
            return ""
        label = insertion_point.replace("_", " ").title()
        for wrong, right in ACRONYMS:
            label = label.replace(wrong, right)
        return f"**{label}:** {row.get('parameter') or ''}\n"

    def cwe(self, definition):
        """
        Parse the CWE the export carries on the finding definition.

        The connector fetches this separately per definition and expects a "CWE-<number>" string; an
        export that does not carry one leaves the CWE at 0, which is the field's default.
        """
        raw = str(definition.get("cwe_id") or "").strip()
        if not raw.startswith("CWE-"):
            return 0
        with suppress(ValueError):
            return int(raw[4:])
        return 0
