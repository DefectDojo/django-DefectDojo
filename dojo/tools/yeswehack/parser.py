import json
import re
from contextlib import suppress
from datetime import datetime
from ipaddress import ip_address
from urllib.parse import urlparse

from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

# Mirrors severityFromString() in the YesWeHack connector's converter. An unrecognised word returns
# nothing at all so the caller can try the next source, which is why this is separate from the
# Info default.
SEVERITY_WORDS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "informative": "Info",
    "none": "Info",
}
DEFAULT_SEVERITY = "Info"

# The connector's applyStatus(): YesWeHack's workflow state decides whether a report is still live,
# and which closed state it landed in. Anything unrecognised stays active.
STATUS_NEW = "new"
STATUS_UNDER_REVIEW = "under_review"
STATUS_ACCEPTED = "accepted"
STATUS_RESOLVED = "resolved"
STATUS_AUTO_CLOSE = "auto_close"
STATUS_WONT_FIX = "wont_fix"
STATUS_INVALID = "invalid"
STATUS_REJECTED = "rejected"
STATUS_DUPLICATE = "duplicate"
STATUS_OUT_OF_SCOPE = "out_of_scope"
STATUS_INFORMATIVE = "informative"

# The shared formatter the connector builds descriptions with: "* **Prefix** text\n" bullets and
# "### Title\n\n" headings.
BULLET = "* **{}** {}\n"
HEADING = "### {}\n\n"

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# The timestamp layouts the connector tries, in order.
DATE_FORMATS = ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d")


# The host DefectDojo accepts: letters, digits, dot, hyphen, underscore or plus, at least two
# characters - or an IP address. See Endpoint.clean().
HOST_PATTERN = re.compile(r"^[A-Za-z0-9_\-+][A-Za-z0-9_.\-+]+$")


class YesWeHackParser:

    """
    Parses a YesWeHack reports export.

    Mirrors pkg/tools/yeswehack/connector/converter.go field for field so a file import and an API
    sync deduplicate against each other instead of producing two copies of everything.

    YesWeHack's workflow state carries real triage information - resolved, won't fix, invalid,
    duplicate - and the connector translates each into the matching DefectDojo state rather than
    importing everything as active.
    """

    def get_scan_types(self):
        # Byte-identical to ScanTypeName in the connector.
        return ["YesWeHack - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "YesWeHack - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a YesWeHack reports export (JSON). Matches the scan type used by the YesWeHack "
            "connector so file and API findings deduplicate. The report's workflow state is "
            "translated into the corresponding DefectDojo state."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the YesWeHack Parser.

        Mirrors the connector's ToFinding:
        - title: the report title, then its local id, then "YesWeHack report <id>".
        - severity: the CVSS criticity, then the priority name, then the priority slug, then Info.
        - description: the local id, bug type and category, scope and endpoint, then the report
          description and impact as headed sections.
        - cvssv3 / cvssv3_score: the reported vector, and the score when above zero.
        - unique_id_from_tool: the numeric report id.
        - vuln_id_from_tool: the local id, falling back to the numeric id.
        - active / verified / is_mitigated / risk_accepted / false_p / duplicate: from the workflow
          state; see apply_status().
        """
        return [
            "title",
            "severity",
            "description",
            "date",
            "cvssv3",
            "cvssv3_score",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "tags",
            "active",
            "verified",
            "is_mitigated",
            "risk_accepted",
            "false_p",
            "duplicate",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the YesWeHack Parser.

        Copied from the YesWeHack block in the Pro connector settings: report ids are globally unique
        on the platform, so the plain hash_code algorithm hashes the unique id alone.
        """
        return ["unique_id_from_tool"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        reports = self.extract_reports(data)

        findings = {}
        for report in reports:
            if not isinstance(report, dict):
                continue
            finding = self.build_finding(report, test)
            findings.setdefault(finding.unique_id_from_tool, finding)
        return list(findings.values())

    def extract_reports(self, data):
        """YesWeHack's list endpoint pages the reports under "items"."""
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("items", "reports"):
                if isinstance(data.get(key), list):
                    return data[key]
        msg = (
            "A YesWeHack export is a JSON object with an 'items' list of reports, or a bare array "
            f"of reports; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def build_finding(self, report, test):
        cvss = report.get("cvss") if isinstance(report.get("cvss"), dict) else {}
        score = cvss.get("score") or 0

        finding = Finding(
            test=test,
            title=self.title(report),
            severity=self.severity(report, cvss),
            description=self.describe(report),
            date=self.date(report.get("created_at")),
            cvssv3=cvss.get("vector") or None,
            unique_id_from_tool=str(report.get("id")),
            vuln_id_from_tool=self.vuln_id(report),
            # A bug-bounty report is a human testing a running target.
            static_finding=False,
            dynamic_finding=True,
        )
        finding.unsaved_tags = ["yeswehack"]
        if score > 0:
            finding.cvssv3_score = score

        cves = self.cves(report)
        if cves:
            finding.unsaved_vulnerability_ids = cves

        status = report.get("status") if isinstance(report.get("status"), dict) else {}
        self.apply_status(finding, status.get("workflow_state"))
        self.attach_endpoint(finding, report)
        return finding

    def title(self, report):
        if report.get("title"):
            return report["title"]
        if report.get("local_id"):
            return report["local_id"]
        return f"YesWeHack report {report.get('id')}"

    def vuln_id(self, report):
        return report.get("local_id") or str(report.get("id"))

    def severity(self, report, cvss):
        """
        Resolve severity from the first source that yields a recognised word.

        The CVSS criticity is preferred, then the priority's name, then its slug. Falling straight to
        Info when the criticity is unset would lose the priority YesWeHack did set.
        """
        for candidate in (cvss.get("criticity"),):
            word = SEVERITY_WORDS.get((candidate or "").strip().lower())
            if word:
                return word
        priority = report.get("priority") if isinstance(report.get("priority"), dict) else {}
        for candidate in (priority.get("name"), priority.get("slug")):
            word = SEVERITY_WORDS.get((candidate or "").strip().lower())
            if word:
                return word
        return DEFAULT_SEVERITY

    def describe(self, report):
        parts = []
        if report.get("local_id"):
            parts.append(BULLET.format("Report:", report["local_id"]))

        bug_type = report.get("bug_type") if isinstance(report.get("bug_type"), dict) else None
        if bug_type:
            if bug_type.get("name"):
                parts.append(BULLET.format("Bug type:", bug_type["name"]))
            category = bug_type.get("category")
            if isinstance(category, dict) and category.get("name"):
                parts.append(BULLET.format("Category:", category["name"]))

        if report.get("scope"):
            parts.append(BULLET.format("Scope:", report["scope"]))
        if report.get("end_point"):
            parts.append(BULLET.format("Endpoint:", report["end_point"]))

        for heading, key in (("Description", "description_html"), ("Impact", "impact")):
            if report.get(key):
                parts.extend(("\n", HEADING.format(heading), report[key], "\n"))
        return "".join(parts)

    def apply_status(self, finding, workflow_state):
        """
        Translate YesWeHack's workflow state into DefectDojo state.

        Importing every report as active would put resolved, rejected and duplicate reports back in
        front of the team; the connector maps each one instead. An unrecognised state stays active,
        which is the safe side of the assumption.
        """
        state = (workflow_state or "").strip().lower()
        finding.active = True
        if state == STATUS_ACCEPTED:
            finding.verified = True
        elif state in {STATUS_RESOLVED, STATUS_AUTO_CLOSE}:
            finding.active = False
            finding.is_mitigated = True
        elif state == STATUS_WONT_FIX:
            finding.active = False
            finding.risk_accepted = True
        elif state in {STATUS_INVALID, STATUS_REJECTED}:
            finding.active = False
            finding.false_p = True
        elif state == STATUS_DUPLICATE:
            finding.active = False
            finding.duplicate = True
        elif state in {STATUS_OUT_OF_SCOPE, STATUS_INFORMATIVE}:
            finding.active = False

    def attach_endpoint(self, finding, report):
        """
        The reported endpoint, falling back to the programme scope.

        Parsed rather than string-split: a researcher writes whatever the scope allows, so the
        value may carry a scheme, a port and a path, and an unparsed "host:port" in the host field
        fails validation for the whole import.
        """
        location = (report.get("end_point") or "").strip() or (report.get("scope") or "").strip()
        if not location:
            return
        parsed = urlparse(location if "//" in location else f"//{location}")
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
            ))
        else:
            # TODO: Delete this after the move to Locations
            finding.unsaved_endpoints.append(Endpoint(
                host=host, protocol=parsed.scheme or None, port=port,
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

    def cves(self, report):
        """The connector scans the title, description, impact and technical information for CVEs."""
        sources = (
            report.get("title") or "",
            report.get("description_html") or "",
            report.get("impact") or "",
            report.get("technical_information_html") or "",
        )
        found, seen = [], set()
        for source in sources:
            for cve in CVE_PATTERN.findall(str(source)):
                upper = cve.upper()
                if upper not in seen:
                    seen.add(upper)
                    found.append(upper)
        return found

    def date(self, timestamp):
        """The connector tries several layouts before giving up, so a non-RFC3339 stamp still dates."""
        trimmed = (timestamp or "").strip()
        if not trimmed:
            return None
        with suppress(ValueError):
            return datetime.fromisoformat(trimmed).date()
        for fmt in DATE_FORMATS:
            with suppress(ValueError):
                return datetime.strptime(trimmed, fmt).date()
        return None
