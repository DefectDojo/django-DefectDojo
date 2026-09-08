import json
import re
from contextlib import suppress
from datetime import date as _date
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
    # "Unknown" is a real SOOS value, not a gap, so it grades rather than being dropped.
    "unknown": "Info",
}
DEFAULT_SEVERITY = "Info"

# SOOS runs several kinds of scan through one API. Only DAST exercises anything, so everything else
# it reports - and anything it reports that is not in this set - is read rather than run.
STATIC_SCAN_TYPES = {"sca", "sast", "csa", "sbom"}

# SOOS-side dispositions that must not resurface as active findings on every sync.
DISMISSED_FALSE_POSITIVE = {"falsepositive", "false_positive"}
DISMISSED_RISK_ACCEPTED = {"accepted"}
DISMISSED_MITIGATED = {"ignored", "dismissed", "resolved", "fixed"}

# The host DefectDojo accepts: letters, digits, dot, hyphen, underscore or plus, at least two
# characters - or an IP address. See Endpoint.clean().
HOST_PATTERN = re.compile(r"^[A-Za-z0-9_\-+][A-Za-z0-9_.\-+]+$")


class SoosParser:

    """
    Parses a SOOS issue export.

    Mirrors pkg/tools/soos/connector/finding_converter field for field so a file import and an API sync
    deduplicate against each other instead of producing two copies of everything.

    SOOS runs SCA, SAST, container, SBOM and DAST scans through ONE API and stamps each issue with its
    scan type, so whether a finding is static or dynamic is decided per issue rather than for the file;
    see is_static(). Only DAST exercises anything.

    A SOOS-side dismissal is carried across so it does not resurface as an active finding on every
    sync - and the three kinds of dismissal are kept apart, because a false positive, an accepted risk
    and a fix are three different statements; see apply_status().
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName.
        return ["SOOS - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "SOOS - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a SOOS issue export (JSON) - SCA, SAST, container, SBOM or DAST issues, each "
            "stamped with its scan type. Matches the scan type used by the SOOS connector so file and "
            "API findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the SOOS Parser.

        Mirrors the connector's ConvertFinding:
        - title / description: SOOS's own, with the scan type noted when there is no prose at all.
        - severity: SOOS's severity word, with "Unknown" grading as Info.
        - mitigation: the remediation text, else naming the fixed version.
        - component_name / component_version: the affected package.
        - file_path / line: for a source finding; the URL becomes an endpoint for a DAST one.
        - cvssv3 / cvssv3_score: the vector and the score.
        - cwe: accepting "CWE-79" or "79".
        - active / false_p / risk_accepted / is_mitigated: the SOOS-side disposition.
        - static_finding / dynamic_finding: decided by the issue's scan type.
        """
        return [
            "title",
            "description",
            "severity",
            "mitigation",
            "references",
            "component_name",
            "component_version",
            "file_path",
            "line",
            "cvssv3",
            "cvssv3_score",
            "cwe",
            "date",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "unsaved_vulnerability_ids",
            "tags",
            "active",
            "false_p",
            "risk_accepted",
            "is_mitigated",
            "static_finding",
            "dynamic_finding",
        ]

    # No get_dedupe_fields: this scan type has no curated hash-field list in the connector settings, so
    # it deduplicates with DefectDojo's default algorithm - which is exactly what the connector's own
    # findings do today. Choosing hash fields here would change those too, which is not this parser's
    # call to make.

    def get_findings(self, filename, test):
        data = json.load(filename)
        return [self.build_finding(row, test) for row in self.rows(data)]

    def rows(self, data):
        """
        Return the issues in the export.

        SOOS pages its lists as {"entries": [...]} and, in places, {"items": [...]} - its own client
        accepts both, so both are read here. A bare array works too.
        """
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
        if isinstance(data, dict):
            for key in ("entries", "items", "issues", "data", "results"):
                if isinstance(data.get(key), list):
                    return [row for row in data[key] if isinstance(row, dict)]

        msg = (
            "A SOOS export is the issues response, a JSON object with an 'entries' list; got "
            f"{type(data).__name__}."
        )
        raise TypeError(msg)

    def build_finding(self, row, test):
        scan_type = str(row.get("scanType") or "").strip().lower()
        static = self.is_static(scan_type)
        package = str(row.get("packageName") or "")

        finding = Finding(
            test=test,
            title=str(row.get("title") or "") or None,
            description=self.describe(row),
            severity=self.severity(row),
            mitigation=self.mitigation(row, package) or None,
            references=str(row.get("references") or "") or None,
            component_name=package or None,
            component_version=str(row.get("packageVersion") or "") or None,
            file_path=str(row.get("fileName") or "") or None,
            line=self.integer(row.get("line")) or None,
            cvssv3=str(row.get("cvssVector") or "") or None,
            cwe=self.cwe(row),
            unique_id_from_tool=str(row.get("id") or "") or None,
            # Only a DAST issue is exercised; SCA, SAST, container and SBOM all inspect artifacts.
            static_finding=static,
            dynamic_finding=not static,
        )
        finding.cvssv3_score = self.number(row.get("cvssScore"))
        finding.unsaved_tags = [scan_type] if scan_type else []

        if cve := str(row.get("cve") or "").strip():
            finding.unsaved_vulnerability_ids = [cve]
            finding.vuln_id_from_tool = cve
        if date := self.date(row.get("firstDetected")):
            finding.date = date

        self.add_endpoint(finding, str(row.get("url") or "").strip())
        self.apply_status(finding, str(row.get("status") or ""))
        return finding

    def is_static(self, scan_type):
        """
        Whether the issue's scan type inspects an artifact rather than running it.

        SOOS puts every kind of scan behind one API, so this is decided per ISSUE. DAST is dynamic, and
        so is an UNRECOGNISED or absent scan type: the connector reads its lookup table with a Go map
        access, which yields false for a missing key just as it does for the dast entry. Mirrored rather
        than corrected, and noted in the PR - a new SOOS scan type would arrive as dynamic.
        """
        return scan_type in STATIC_SCAN_TYPES

    def severity(self, row):
        """
        SOOS's severity word.

        "Unknown" is a real SOOS value rather than a gap, and it grades as Info instead of being
        dropped - a finding it could not grade is still a finding.
        """
        label = str(row.get("severity") or "").strip().lower()
        return SEVERITY_BY_NAME.get(label, DEFAULT_SEVERITY)

    def describe(self, row):
        """
        SOOS's own prose, and when there is none, which scan reported the issue.

        An empty body would read as though the data had been lost in transit.
        """
        if description := str(row.get("description") or "").strip():
            return description
        if scan_type := str(row.get("scanType") or "").strip():
            return f"Reported by the SOOS {scan_type} scan."
        return "Reported by SOOS."

    def mitigation(self, row, package):
        """The remediation text, else naming the fixed version - and the package when it is known."""
        if remediation := str(row.get("remediation") or "").strip():
            return remediation
        fixed = str(row.get("fixedVersion") or "").strip()
        if not fixed:
            return ""
        if component := package.strip():
            return f"Upgrade {component} to {fixed} or later."
        return f"Upgrade to {fixed} or later."

    def cwe(self, row):
        """The CWE as a number, accepting "CWE-79" or "79"."""
        digits = str(row.get("cwe") or "").strip().upper().removeprefix("CWE-")
        with suppress(ValueError):
            return int(digits)
        return 0

    def apply_status(self, finding, status):
        """
        Carry a SOOS-side dismissal across, so it does not resurface as active on every sync.

        The three kinds are kept apart because they are three different statements: a false positive was
        never real, an accepted risk is real and signed off, and a resolved or ignored issue is treated
        as dealt with. Anything else - including an unrecognised status - stays ACTIVE.
        """
        normalised = str(status or "").strip().lower().replace(" ", "")

        if normalised in DISMISSED_FALSE_POSITIVE:
            finding.active = False
            finding.false_p = True
        elif normalised in DISMISSED_RISK_ACCEPTED:
            finding.active = False
            finding.risk_accepted = True
        elif normalised in DISMISSED_MITIGATED:
            finding.active = False
            finding.is_mitigated = True
        else:
            finding.active = True

    def add_endpoint(self, finding, url):
        """
        The DAST location, when the issue has one.

        A source finding has a file path instead, and no URL at all.
        """
        if not url:
            return
        with suppress(ValueError):
            parsed = urlparse(url)
            host = parsed.hostname or ""
            if not host or not self.usable_host(host):
                # A host DefectDojo rejects makes Endpoint.clean() raise, which fails the WHOLE
                # import. The URL is still in the description either way.
                return
            path = (parsed.path or "").lstrip("/")
            if locations_enabled():
                finding.unsaved_locations.append(LocationData.url(
                    host=host, protocol=parsed.scheme or None, port=parsed.port,
                    path=path, query=parsed.query,
                ))
            else:
                # TODO: Delete this after the move to Locations
                finding.unsaved_endpoints.append(Endpoint(
                    host=host, protocol=parsed.scheme or None, port=parsed.port,
                    path=path or None, query=parsed.query or None,
                ))

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
        When SOOS first detected the issue, cut back to the calendar date.

        The connector cuts at the "T" because it hands the API a string; this reads the same value as a
        date and skips one that is not a date rather than failing the import.
        """
        text = str(value or "").strip()
        if len(text) < 10:
            return None
        with suppress(ValueError):
            return _date.fromisoformat(text.split("T")[0])
        return None

    def number(self, value):
        if isinstance(value, bool) or value is None:
            return 0.0
        if isinstance(value, int | float):
            return float(value)
        if isinstance(value, str):
            with suppress(ValueError):
                return float(value.strip() or 0)
        return 0.0

    def integer(self, value):
        return int(self.number(value))
