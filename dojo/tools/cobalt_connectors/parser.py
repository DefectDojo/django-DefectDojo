import json
from contextlib import suppress
from datetime import datetime

from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
DEFAULT_SEVERITY = "Info"

# Cobalt's pentest workflow states, with the meaning the connector documents for each.
STATE_CARRIED_OVER = "carried_over"    # carried over from a previous pentest
STATE_CHECK_FIX = "check_fix"          # fix being verified by the pentest team
STATE_DUPLICATE = "duplicate"          # duplicate of another finding in the pentest
STATE_INVALID = "invalid"              # determined to be a false positive
STATE_NEED_FIX = "need_fix"            # verified and valid, awaiting a fix
STATE_NEW = "new"                      # not yet verified by the pentest team
STATE_OUT_OF_SCOPE = "out_of_scope"    # outside the scope of the pentest
STATE_TRIAGING = "triaging"            # being verified by the pentest team
STATE_VALID_FIX = "valid_fix"          # fix has been verified
STATE_WONT_FIX = "wont_fix"            # risk has been accepted

# Every documented state is importable; anything Cobalt adds later is not, so an unknown state is
# skipped rather than guessed at.
IMPORTABLE_STATES = frozenset({
    STATE_CARRIED_OVER, STATE_CHECK_FIX, STATE_DUPLICATE, STATE_INVALID, STATE_NEED_FIX,
    STATE_NEW, STATE_OUT_OF_SCOPE, STATE_TRIAGING, STATE_VALID_FIX, STATE_WONT_FIX,
})

LOG_ACTION_CREATED = "created"

# DefectDojo's title column.
MAX_TITLE_LENGTH = 511
TITLE_PLACEHOLDER = "..."


class CobaltConnectorsParser:

    """
    Parses a Cobalt.io findings export.

    Mirrors pkg/tools/cobalt/connector/converter.go field for field so a file import and an API sync
    deduplicate against each other instead of producing two copies of everything.

    Note DefectDojo also ships a `cobalt` parser for Cobalt's CSV export, under the scan type
    "Cobalt.io Scan". This is a separate parser for the connector's own scan type and JSON shape.
    """

    def get_scan_types(self):
        # Byte-identical to ScanTypeName in the connector, and distinct from the CSV parser's
        # "Cobalt.io Scan".
        return ["Cobalt.io - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Cobalt.io - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Cobalt.io findings export (JSON). Matches the scan type used by the Cobalt.io "
            "connector so file and API findings deduplicate. The pentest state is translated into "
            "the corresponding DefectDojo state."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Cobalt.io Parser.

        Mirrors the connector's toFinding:
        - title: the finding title, shortened on a word boundary if it exceeds the title column.
        - severity: Cobalt's severity word; anything unrecognised Info.
        - date: the timestamp of the "created" log entry, falling back to created_at.
        - last_status_update: the latest timestamp in the finding's log.
        - description: the description, then impact and likelihood, then the Cobalt.io deep link.
        - mitigation: Cobalt's suggested fix.
        - steps_to_reproduce: the proof of concept.
        - severity_justification: Cobalt's own justification text.
        - cvssv3 / cvssv3_score: the first CVSS entry whose version starts with 3.
        - cwe: the first CWE id above zero.
        - unique_id_from_tool / vuln_id_from_tool: both the Cobalt finding id.
        """
        return [
            "title",
            "severity",
            "date",
            "last_status_update",
            "description",
            "mitigation",
            "steps_to_reproduce",
            "severity_justification",
            "url",
            "cvssv3",
            "cvssv3_score",
            "cwe",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "active",
            "verified",
            "false_p",
            "duplicate",
            "out_of_scope",
            "risk_accepted",
            "is_mitigated",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Cobalt.io Parser.

        Copied from the Cobalt block in the Pro connector settings: finding ids are stable, so the
        plain hash_code algorithm hashes the unique id alone.
        """
        return ["unique_id_from_tool"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        entries = self.extract_entries(data)

        findings = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            resource, ui_url = self.unwrap(entry)
            state = (resource.get("state") or "").strip().lower()
            if state not in IMPORTABLE_STATES:
                continue
            finding = self.build_finding(resource, ui_url, state, test)
            findings.setdefault(finding.unique_id_from_tool, finding)
        return list(findings.values())

    def extract_entries(self, data):
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("data", "findings"):
                if isinstance(data.get(key), list):
                    return data[key]
        msg = (
            "A Cobalt.io export is a JSON object with a 'data' list of findings, or a bare array of "
            f"findings; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def unwrap(self, entry):
        """
        Separate the finding resource from its links.

        Cobalt nests each finding under "resource" and puts the human-facing deep link outside it, at
        links.ui.url - so reading the entry directly would lose the link. An already-flattened export
        is accepted by falling back to the entry itself.
        """
        resource = entry.get("resource") if isinstance(entry.get("resource"), dict) else entry
        ui_url = ""
        links = entry.get("links")
        if isinstance(links, dict):
            ui = links.get("ui")
            if isinstance(ui, dict):
                ui_url = ui.get("url") or ""
        if not ui_url:
            ui_url = resource.get("ui_url") or ""
        return resource, ui_url

    def build_finding(self, resource, ui_url, state, test):
        is_mitigated = state == STATE_VALID_FIX
        false_p = state == STATE_INVALID
        out_of_scope = state == STATE_OUT_OF_SCOPE

        finding = Finding(
            test=test,
            title=self.shorten_title(resource.get("title") or ""),
            severity=SEVERITY_MAP.get(
                (resource.get("severity") or "").strip().lower(), DEFAULT_SEVERITY,
            ),
            date=self.created_date(resource),
            last_status_update=self.last_status_update(resource),
            description=self.describe(resource, ui_url),
            mitigation=resource.get("suggested_fix") or None,
            steps_to_reproduce=resource.get("proof_of_concept") or None,
            severity_justification=resource.get("severity_justification") or None,
            url=ui_url or None,
            unique_id_from_tool=resource.get("id"),
            vuln_id_from_tool=resource.get("id") or None,
            # A finding is closed when it is fixed, invalid or out of scope. Note a duplicate or an
            # accepted risk stays ACTIVE: the connector flags those without closing them.
            active=not (is_mitigated or false_p or out_of_scope),
            # Cobalt only moves a finding past new/triaging once the pentest team has verified it.
            verified=state not in {STATE_NEW, STATE_TRIAGING},
            false_p=false_p,
            duplicate=state == STATE_DUPLICATE,
            out_of_scope=out_of_scope,
            risk_accepted=state == STATE_WONT_FIX,
            is_mitigated=is_mitigated,
            # A pentest finding comes from a human testing a running target.
            static_finding=False,
            dynamic_finding=True,
        )

        cwe = self.first_cwe(resource.get("cwes"))
        if cwe:
            finding.cwe = cwe
        vector, score = self.cvss_v3(resource.get("cvsss"))
        if vector:
            finding.cvssv3 = vector
        if score:
            finding.cvssv3_score = score
        cves = self.cves(resource.get("cves"))
        if cves:
            finding.unsaved_vulnerability_ids = cves

        self.attach_targets(finding, resource.get("affected_targets"))
        return finding

    def shorten_title(self, title):
        """
        Trim to the title column, cutting at the last space so a word is not split.

        The connector prefers a clean word boundary over using the full budget.
        """
        trimmed = title.strip()
        if len(trimmed) <= MAX_TITLE_LENGTH:
            return trimmed
        cut = MAX_TITLE_LENGTH - len(TITLE_PLACEHOLDER)
        truncated = trimmed[:cut]
        last_space = truncated.rfind(" ")
        if last_space > 0:
            truncated = truncated[:last_space]
        return truncated.rstrip() + TITLE_PLACEHOLDER

    def created_date(self, resource):
        """
        The timestamp of the "created" log entry, falling back to created_at.

        The log is authoritative because Cobalt can carry a finding over from an earlier pentest, in
        which case created_at is the carry-over date rather than when it was found.
        """
        for entry in self.log_entries(resource):
            if (entry.get("action") or "").strip().lower() == LOG_ACTION_CREATED:
                parsed = self.date(entry.get("timestamp"))
                if parsed:
                    return parsed
        return self.date(resource.get("created_at"))

    def last_status_update(self, resource):
        """The latest timestamp anywhere in the log, which is when the state last moved."""
        latest = None
        for entry in self.log_entries(resource):
            parsed = self.date(entry.get("timestamp"))
            if parsed and (latest is None or parsed > latest):
                latest = parsed
        return latest

    def log_entries(self, resource):
        log = resource.get("log")
        return [e for e in log if isinstance(e, dict)] if isinstance(log, list) else []

    def describe(self, resource, ui_url):
        parts = []
        if resource.get("description"):
            parts.append(resource["description"])

        details = []
        # Cobalt sends these as numbers, and the connector renders them as-is.
        if self.present(resource.get("impact")):
            details.append(f"- Impact: {resource['impact']}")
        if self.present(resource.get("likelihood")):
            details.append(f"- Likelihood: {resource['likelihood']}")
        if details:
            parts.append("Cobalt.io details:\n" + "\n".join(details))

        if ui_url:
            parts.append(f"Cobalt.io link:\n{ui_url}")
        return "\n\n".join(parts)

    def present(self, value):
        """
        Report whether Cobalt supplied a value.

        Zero is a real impact and likelihood score, so a plain truthiness check would drop it and
        silently omit the line. Only None and the empty string count as absent.
        """
        return value not in {None, ""}

    def first_cwe(self, cwes):
        if not isinstance(cwes, list):
            return 0
        for cwe in cwes:
            if isinstance(cwe, dict) and (cwe.get("id") or 0) > 0:
                return cwe["id"]
        return 0

    def cvss_v3(self, entries):
        """
        The first CVSS entry whose version starts with "3".

        Cobalt can report several versions, and Finding.cvssv3 is a v3 field - taking whichever came
        first would put a v2 or v4 vector in it.
        """
        if not isinstance(entries, list):
            return "", 0
        for entry in entries:
            if isinstance(entry, dict) and str(entry.get("version") or "").startswith("3"):
                return entry.get("vector") or "", entry.get("score") or 0
        return "", 0

    def cves(self, entries):
        if not isinstance(entries, list):
            return []
        found = []
        for entry in entries:
            if isinstance(entry, dict) and entry.get("cve_id"):
                found.append(entry["cve_id"])
            elif isinstance(entry, str) and entry:
                found.append(entry)
        return found

    def attach_targets(self, finding, targets):
        """Cobalt names the hosts or applications the pentest covered."""
        if not isinstance(targets, list):
            return
        for target in targets:
            host = str(target or "").strip()
            if not host:
                continue
            host = host.split("//")[-1].split("/")[0]
            if not host:
                continue
            if settings.V3_FEATURE_LOCATIONS:
                finding.unsaved_locations.append(LocationData.url(host=host))
            else:
                # TODO: Delete this after the move to Locations
                finding.unsaved_endpoints.append(Endpoint(host=host))

    def date(self, timestamp):
        trimmed = (timestamp or "").strip()
        if not trimmed:
            return None
        with suppress(ValueError):
            return datetime.fromisoformat(trimmed).date()
        return None
