import json
import re
from contextlib import suppress
from datetime import datetime
from ipaddress import ip_address

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

# Intruder's snooze reasons, which is how it records triage.
SNOOZE_FALSE_POSITIVE = "FALSE_POSITIVE"
SNOOZE_ACCEPT_RISK = "ACCEPT_RISK"
SNOOZE_MITIGATING_CONTROL = "MITIGATING_CONTROLS"

# The advisory identifiers the connector's shared extractor recognises in free text.
VULNERABILITY_ID_PATTERN = re.compile(
    r"CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|GO-\d{4}-\d+|RHSA-\d{4}:\d+",
)

# The host DefectDojo accepts: letters, digits, dot, hyphen, underscore or plus, at least two
# characters - or an IP address. See Endpoint.clean().
HOST_PATTERN = re.compile(r"^[A-Za-z0-9_\-+][A-Za-z0-9_.\-+]+$")


class IntruderParser:

    """
    Parses an Intruder issues export.

    Mirrors pkg/tools/intruder/connector/finding_converter field for field so a file import and an API
    sync deduplicate against each other instead of producing two copies of everything.

    Intruder separates an issue - the weakness, its description and remediation - from its occurrences,
    which are the targets it was found on. One finding is produced per occurrence, so an export needs
    both; see extract().
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName. Note it does NOT follow the
        # "<Vendor> - Connectors Import" pattern, so it cannot be derived - it has to be copied.
        return ["Intruder API Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Intruder API Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import an Intruder issues export (JSON). Matches the scan type used by the Intruder "
            "connector so file and API findings deduplicate. Include each issue's occurrences - the "
            "occurrence is the finding."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Intruder Parser.

        Mirrors the connector's ConvertOccurrence:
        - title: the issue title, shared by every occurrence of it.
        - severity: the issue's severity label; anything unrecognised is Info.
        - description: the target, port, protocol, first-seen date, exploit likelihood and any extra
          information, then the issue's own prose.
        - mitigation: the issue's remediation text.
        - cvssv3_score: the occurrence's score, falling back to the issue's.
        - date: when the occurrence was first seen.
        - active / false_p / risk_accepted: from the occurrence's snooze state; see triage().
        - unique_id_from_tool: the occurrence id, which is stable per issue, target and port.
        - vuln_id_from_tool: the issue id.
        """
        return [
            "title",
            "severity",
            "date",
            "description",
            "mitigation",
            "cvssv3_score",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "unsaved_vulnerability_ids",
            "tags",
            "active",
            "false_p",
            "risk_accepted",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Intruder Parser.

        Copied from the Intruder block in the Pro connector settings, which - unlike most connector
        scan types - uses the plain hash_code algorithm rather than pairing it with the unique id. The
        occurrence id is part of the HASH instead, with title and severity guarding against id reuse.
        """
        return ["unique_id_from_tool", "title", "severity"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        issues, occurrences = self.extract(data)

        findings = []
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            findings.extend(
                self.build_finding(issue, occurrence, test)
                for occurrence in self.occurrences_for(issue, occurrences)
            )
        return findings

    def extract(self, data):
        """
        Return the issues and the occurrences of each.

        Intruder pages every list under "results". The occurrences come from a second call, one per
        issue, and carry no issue id of their own, so an export keys them by issue id or nests them on
        the issue.
        """
        occurrences = {}
        issues = None

        if isinstance(data, list):
            issues = data
        elif isinstance(data, dict):
            for key in ("results", "issues"):
                if isinstance(data.get(key), list):
                    issues = data[key]
                    break
            occurrences = self.index_occurrences(data)

        if issues is None:
            msg = (
                "An Intruder export is the issues response, a JSON object with a 'results' list; got "
                f"{type(data).__name__}."
            )
            raise TypeError(msg)
        return issues, occurrences

    def index_occurrences(self, data):
        """The occurrences as a map keyed by issue id."""
        source = data.get("occurrences")
        if not isinstance(source, dict):
            return {}
        indexed = {}
        for issue_id, value in source.items():
            # Accept the occurrences endpoint's own paged response as well as a bare list.
            rows = value.get("results") if isinstance(value, dict) else value
            if isinstance(rows, list):
                indexed[str(issue_id)] = [row for row in rows if isinstance(row, dict)]
        return indexed

    def occurrences_for(self, issue, occurrences):
        """The occurrences nested on the issue, else those indexed by its id."""
        nested = issue.get("occurrences")
        if isinstance(nested, list):
            return [row for row in nested if isinstance(row, dict)]
        if isinstance(nested, dict) and isinstance(nested.get("results"), list):
            return [row for row in nested["results"] if isinstance(row, dict)]
        # Intruder's own issue object carries "occurrences" as a URL string, which is not a list -
        # that is the second call the export has to include.
        return occurrences.get(str(issue.get("id")), [])

    def build_finding(self, issue, occurrence, test):
        finding = Finding(
            test=test,
            title=str(issue.get("title") or ""),
            severity=self.severity(issue),
            description=self.describe(issue, occurrence),
            mitigation=str(issue.get("remediation") or ""),
            unique_id_from_tool=self.identifier(occurrence.get("occurrence_id")),
            vuln_id_from_tool=self.identifier(issue.get("id")),
            # Intruder scans live hosts and services.
            static_finding=False,
            dynamic_finding=True,
        )
        finding.cvssv3_score = self.score(issue, occurrence)
        finding.unsaved_tags = self.tags(occurrence)

        if identifiers := self.vulnerability_ids(issue, occurrence):
            finding.unsaved_vulnerability_ids = identifiers
        if date := self.date(occurrence):
            finding.date = date

        self.triage(finding, occurrence)
        self.attach_endpoint(finding, occurrence)
        return finding

    def identifier(self, value):
        """Intruder's ids are integers; the connector renders them as strings."""
        if isinstance(value, bool) or value is None:
            return None
        if isinstance(value, int | float):
            return str(int(value))
        text = str(value).strip()
        return text or None

    def severity(self, issue):
        label = str(issue.get("severity") or "").strip().lower()
        return SEVERITY_BY_LABEL.get(label, DEFAULT_SEVERITY)

    def score(self, issue, occurrence):
        """
        The occurrence's score, falling back to the issue's.

        The same weakness scores differently per target - a service reachable from the internet is not
        the same risk as one behind a firewall - so the occurrence's own score wins.
        """
        for source in (occurrence, issue):
            value = source.get("cvss_score")
            if isinstance(value, int | float) and not isinstance(value, bool) and value != 0:
                return float(value)
        return 0.0

    def triage(self, finding, occurrence):
        """
        Intruder records triage by snoozing an occurrence, with a reason.

        A snoozed occurrence is inactive, and the reason decides whether it is a false positive or an
        accepted risk. A snooze reason the connector does not recognise leaves the finding inactive
        without either flag - it is still triaged, just not in a way DefectDojo has a field for.
        """
        if not occurrence.get("snoozed"):
            finding.active = True
            return
        finding.active = False
        reason = str(occurrence.get("snooze_reason") or "").strip()
        if reason == SNOOZE_FALSE_POSITIVE:
            finding.false_p = True
        elif reason in {SNOOZE_ACCEPT_RISK, SNOOZE_MITIGATING_CONTROL}:
            finding.risk_accepted = True

    def vulnerability_ids(self, issue, occurrence):
        """
        The occurrence's CVEs, then any identifier in the issue's title or description.

        Order is preserved and duplicates dropped, as the connector does.
        """
        candidates = []
        cves = occurrence.get("cves")
        if isinstance(cves, list):
            candidates.extend(str(cve) for cve in cves)
        prose = "|".join([str(issue.get("title") or ""), str(issue.get("description") or "")])
        candidates.extend(VULNERABILITY_ID_PATTERN.findall(prose))

        identifiers = []
        for candidate in candidates:
            trimmed = candidate.strip()
            if trimmed and trimmed not in identifiers:
                identifiers.append(trimmed)
        return identifiers

    def date(self, occurrence):
        """Intruder timestamps in RFC 3339; only the date is kept."""
        first_seen = str(occurrence.get("first_seen_at") or "").strip()
        if not first_seen:
            return None
        with suppress(ValueError):
            return datetime.strptime(first_seen.split("T")[0], "%Y-%m-%d").date()
        return None

    def describe(self, issue, occurrence):
        """
        The connector's shared formatter: prefixed bullets, then a level-3 Description heading.

        Note the target line prefers the DISPLAY address while the endpoint prefers the target - the
        display address is what a person recognises, the target is what was scanned.
        """
        bullets = []

        def add(prefix, value):
            text = str(value or "").strip()
            if text:
                bullets.append(f"* **{prefix}** {text}")

        target = str(occurrence.get("display_address") or "").strip()
        if not target:
            target = str(occurrence.get("target") or "").strip()
        add("Target:", target)
        add("Port:", occurrence.get("port"))
        add("Protocol:", occurrence.get("protocol"))
        add("First seen:", occurrence.get("first_seen_at"))
        add("Exploit likelihood:", occurrence.get("exploit_likelihood"))

        extra = occurrence.get("extra_info")
        if isinstance(extra, dict):
            # Sorted because a Go map has no order, and matching that keeps the two paths identical.
            for key in sorted(extra):
                add(f"{key}:", extra[key])

        parts = ["\n".join(bullets) + "\n"] if bullets else []
        if prose := str(issue.get("description") or "").strip():
            parts.append("\n### Description\n\n" + prose + "\n")
        return "".join(parts).rstrip("\n") + "\n" if parts else ""

    def tags(self, occurrence):
        tags = ["intruder"]
        if target := str(occurrence.get("target") or "").strip():
            tags.append(f"target:{target}")
        return tags

    def attach_endpoint(self, finding, occurrence):
        """
        Record the scanned target.

        The connector emits "<host>:<port>" as an endpoint string; here host and port are set as
        separate fields, which is the same outcome without the string round-trip. A port of "0" means
        Intruder had none, and the connector drops it rather than recording port zero.
        """
        host = str(occurrence.get("target") or "").strip()
        if not host:
            host = str(occurrence.get("display_address") or "").strip()
        if not host or not self.usable_host(host):
            return

        port = None
        raw_port = str(occurrence.get("port") or "").strip()
        if raw_port and raw_port != "0":
            with suppress(ValueError):
                port = int(raw_port)

        if locations_enabled():
            finding.unsaved_locations.append(LocationData.url(host=host, port=port))
        else:
            # TODO: Delete this after the move to Locations
            finding.unsaved_endpoints.append(Endpoint(host=host, port=port))

    def usable_host(self, value):
        """
        Whether DefectDojo will accept this as an endpoint host.

        A host is letters, digits, dot, hyphen, underscore or plus, or an IP address. Anything else
        makes Endpoint.clean() raise, and that fails the whole import rather than the one finding.
        The target is still in the description.
        """
        if HOST_PATTERN.match(value):
            return True
        with suppress(ValueError):
            ip_address(value)
            return True
        return False
