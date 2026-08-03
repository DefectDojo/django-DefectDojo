import json
import re
from urllib.parse import urlparse

from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

# Bugcrowd grades submissions P1 to P5. Mirrors severityFromPriority() in the connector.
SEVERITY_BY_PRIORITY = {1: "Critical", 2: "High", 3: "Medium", 4: "Low"}
DEFAULT_SEVERITY = "Info"

STATE_NEW = "new"
STATE_TRIAGED = "triaged"
STATE_TRIAGING = "triaging"
STATE_UNRESOLVED = "unresolved"
STATE_RESOLVED = "resolved"
STATE_INFORMATIONAL = "informational"
STATE_OUT_OF_SCOPE = "out_of_scope"
STATE_NOT_REPRODUCIBLE = "not_reproducible"
STATE_NOT_APPLICABLE = "not_applicable"

# The states the connector imports. Note "triaging" is deliberately absent: a submission still being
# triaged has no confirmed verdict yet, so the connector waits rather than importing a maybe.
IMPORTABLE_STATES = frozenset({
    STATE_NEW, STATE_OUT_OF_SCOPE, STATE_NOT_APPLICABLE, STATE_NOT_REPRODUCIBLE,
    STATE_TRIAGED, STATE_UNRESOLVED, STATE_RESOLVED, STATE_INFORMATIONAL,
})

# DefectDojo's title column is 511 characters.
TITLE_MAX_LENGTH = 511
TITLE_ELLIPSIS = "..."

# Titles matching this need no rewriting; anything else has its awkward characters replaced.
TITLE_AUTHORIZED = re.compile(r"^[a-zA-Z0-9_\s+,\-.]*$")
WHITESPACE_RUN = re.compile(r"\s+")

TRACKER_BASE = "https://tracker.bugcrowd.com/"


class BugcrowdConnectorsParser:

    """
    Parses a Bugcrowd submissions export.

    Mirrors pkg/tools/bugcrowd/connector/converter.go field for field so a file import and an API
    sync deduplicate against each other instead of producing two copies of everything.

    Note DefectDojo also ships a `bugcrowd` parser for Bugcrowd's CSV export, under the scan type
    "BugCrowd Scan". This is a separate parser for the connector's own scan type and JSON shape; the
    two do not interfere.
    """

    def get_scan_types(self):
        # Byte-identical to ScanTypeName in the connector, and distinct from the CSV parser's
        # "BugCrowd Scan".
        return ["Bugcrowd - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Bugcrowd - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Bugcrowd submissions export (JSON:API). Matches the scan type used by the "
            "Bugcrowd connector so file and API findings deduplicate. Submissions still being "
            "triaged are not imported."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Bugcrowd Parser.

        Mirrors the connector's toFinding:
        - title: the submission title, with awkward characters replaced and shortened to fit.
        - severity: from the Bugcrowd priority, P1 to P4; anything else Info.
        - description: the researcher's description, the priority, the bug URL and the tracker link.
        - mitigation: Bugcrowd's remediation advice.
        - steps_to_reproduce: the researcher's description.
        - references: the tracker link for the submission.
        - unique_id_from_tool: the Bugcrowd submission id.
        - active / verified / false_p / out_of_scope / is_mitigated: from the state; see the
          per-state helpers.
        """
        return [
            "title",
            "severity",
            "date",
            "description",
            "mitigation",
            "steps_to_reproduce",
            "references",
            "unique_id_from_tool",
            "active",
            "verified",
            "false_p",
            "out_of_scope",
            "is_mitigated",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Bugcrowd Parser.

        Copied from the Bugcrowd block in the Pro connector settings: submission ids are globally
        unique on the platform, so the plain hash_code algorithm hashes the unique id alone.
        """
        return ["unique_id_from_tool"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        submissions, program_code = self.extract(data)

        findings = {}
        for submission in submissions:
            if not isinstance(submission, dict):
                continue
            state = self.normalise_state(self.attribute(submission, "state"))
            if state not in IMPORTABLE_STATES:
                continue
            finding = self.build_finding(submission, state, program_code, test)
            findings.setdefault(finding.unique_id_from_tool, finding)
        return list(findings.values())

    def extract(self, data):
        """
        Return the submissions and the programme code.

        The connector reads the programme code from the product's own configuration rather than the
        payload, so an export only carries it if whoever produced it added it. Without one the
        tracker link is still built, just without the programme segment.
        """
        program_code = ""
        if isinstance(data, list):
            return data, program_code
        if isinstance(data, dict):
            program_code = data.get("program_code") or data.get("programCode") or ""
            for key in ("data", "submissions"):
                if isinstance(data.get(key), list):
                    return data[key], program_code
        msg = (
            "A Bugcrowd export is a JSON:API object with a 'data' list of submissions, or a bare "
            f"array of submissions; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def build_finding(self, submission, state, program_code, test):
        link = self.tracker_link(program_code, self.self_link(submission))
        priority = self.attribute(submission, "severity")
        description = self.attribute(submission, "description") or ""
        bug_url = (self.attribute(submission, "bug_url") or "").strip()

        severity = SEVERITY_BY_PRIORITY.get(priority, DEFAULT_SEVERITY)
        active = self.is_active(state)
        if state == STATE_NOT_APPLICABLE:
            # A submission Bugcrowd judged not applicable is neither open nor graded.
            active = False
            severity = DEFAULT_SEVERITY

        finding = Finding(
            test=test,
            title=self.title(self.attribute(submission, "title") or ""),
            severity=severity,
            date=self.date_only(self.attribute(submission, "submitted_at")),
            description=self.describe(description, priority, bug_url, link),
            mitigation=self.attribute(submission, "remediation_advice") or None,
            steps_to_reproduce=description or None,
            references=link,
            unique_id_from_tool=submission.get("id"),
            active=active,
            verified=self.is_verified(state),
            false_p=state == STATE_NOT_REPRODUCIBLE,
            out_of_scope=state == STATE_OUT_OF_SCOPE,
            is_mitigated=state == STATE_RESOLVED,
            # A bug-bounty submission is a researcher testing a running target.
            static_finding=False,
            dynamic_finding=True,
        )
        self.attach_endpoint(finding, bug_url)
        return finding

    def attribute(self, submission, name):
        """
        Read a JSON:API attribute, accepting an already-flattened export.

        Bugcrowd nests everything but the id under "attributes"; a script-produced export may have
        flattened it.
        """
        attributes = submission.get("attributes")
        if isinstance(attributes, dict) and name in attributes:
            return attributes[name]
        return submission.get(name)

    def self_link(self, submission):
        links = submission.get("links")
        if isinstance(links, dict) and links.get("self"):
            return links["self"]
        return submission.get("self_link") or ""

    def tracker_link(self, program_code, self_link):
        return f"{TRACKER_BASE}{program_code}{self_link}"

    def normalise_state(self, state):
        """Bugcrowd writes these with either hyphens or underscores, so both are normalised."""
        return (state or "").strip().lower().replace("-", "_")

    def is_active(self, state):
        """
        An unresolved submission is always active; otherwise a closed state closes it.

        Note "informational" counts as closed here even though it is imported, so a courtesy report
        does not sit in the open queue.
        """
        if state == STATE_UNRESOLVED:
            return True
        closed = state in {
            STATE_RESOLVED, STATE_NOT_REPRODUCIBLE, STATE_OUT_OF_SCOPE, STATE_INFORMATIONAL,
        }
        return not closed

    def is_verified(self, state):
        """
        Triaged means a human confirmed it.

        The connector also treats anything past the new/triaging stage as verified, on the basis that
        Bugcrowd only moves a submission on once someone has looked at it.
        """
        return state == STATE_TRIAGED or state not in {STATE_NEW, STATE_TRIAGING}

    def title(self, title):
        """Replace the characters DefectDojo dislikes, then collapse whitespace and shorten."""
        return self.shorten_title(self.sanitize_title(title))

    def sanitize_title(self, title):
        if TITLE_AUTHORIZED.match(title):
            return title
        return title.replace(":", " ").replace('"', " ").replace("@", "at")

    def shorten_title(self, title):
        collapsed = WHITESPACE_RUN.sub(" ", title).strip()
        if len(collapsed) <= TITLE_MAX_LENGTH:
            return collapsed
        return collapsed[:TITLE_MAX_LENGTH - len(TITLE_ELLIPSIS)] + TITLE_ELLIPSIS

    def describe(self, description, priority, bug_url, link):
        """The connector's fixed layout, including the markdown self-links."""
        return "\n".join([
            description,
            "",
            "Bugcrowd details:",
            f"- Severity: P{priority}",
            f"- Bug Url: [{bug_url}]({bug_url})",
            "",
            f"Bugcrowd link: [{link}]({link})",
        ])

    def date_only(self, timestamp):
        """The connector takes the leading date portion rather than parsing the timestamp."""
        trimmed = (timestamp or "").strip()
        if not trimmed:
            return None
        return trimmed.split("T")[0]

    def attach_endpoint(self, finding, bug_url):
        """
        Record the reported URL.

        The connector prefixes a bare host with "//" so DefectDojo's URI parser keeps it in the host
        field rather than the path, and drops the value entirely when no host can be read.
        """
        if not bug_url:
            return
        candidate = bug_url if "://" in bug_url else f"//{bug_url}"
        parsed = urlparse(candidate)
        if not parsed.hostname:
            return
        path = parsed.path or None
        if settings.V3_FEATURE_LOCATIONS:
            finding.unsaved_locations.append(LocationData.url(
                host=parsed.hostname, protocol=parsed.scheme or None,
                port=parsed.port, path=path,
            ))
        else:
            # TODO: Delete this after the move to Locations
            finding.unsaved_endpoints.append(Endpoint(
                host=parsed.hostname, protocol=parsed.scheme or None,
                port=parsed.port, path=path.lstrip("/") if path else None,
            ))
