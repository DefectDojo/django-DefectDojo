import json
from contextlib import suppress
from datetime import UTC, datetime

from dojo.models import Finding

# Verbatim from Nightfall's ViolationRisk enum.
SEVERITY_BY_RISK = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "NO_RISK": "Info",
    "UNSPECIFIED": "Info",
}
DEFAULT_SEVERITY = "Info"

# Verbatim from Nightfall's ViolationState enum.
STATE_ACTIVE = "ACTIVE"
STATE_PENDING = "PENDING"
STATE_RESOLVED = "RESOLVED"
STATE_EXPIRED = "EXPIRED"

# An API key Nightfall could reach, or whose signature it verified, is a live credential.
LIVE_KEY_STATUSES = {"ACTIVE", "SIGNATURE_VERIFIED"}

# Each integration keeps its own metadata block, and only one of them is ever set. The order is the
# connector's, because it decides which block wins if a violation somehow carries two.
LOCATION_BY_INTEGRATION = (
    ("slackMetadata", " / ", ("workspaceName", "location")),
    ("githubMetadata", "/", ("organization", "repository")),
    ("gdriveMetadata", " / ", ("drive", "fileName")),
    ("jiraMetadata", " ", ("projectName", "ticketNumber")),
    ("confluenceMetadata", " / ", ("spaceName", "itemName")),
    ("salesforceMetadata", " / ", ("orgName", "objectName")),
    ("zendeskMetadata", " ", ("ticketTitle", "ticketID")),
    ("notionMetadata", " / ", ("workspaceName", "pageTitle")),
    ("m365TeamsMetadata", " / ", ("teamName", "channelName")),
    ("m365OnedriveMetadata", " / ", ("driveOwnerName", "driveItemName")),
    ("browserMetadata", " / ", ("browserName", "location")),
    ("inlineEmailMetadata", " / ", ("domain", "subject")),
)

# The link field each integration's metadata block carries, in the same precedence order.
LINK_BY_INTEGRATION = (
    ("slackMetadata", "messagePermalink"),
    ("githubMetadata", "githubPermalink"),
    ("gdriveMetadata", "fileLink"),
    ("jiraMetadata", "ticketLink"),
    ("confluenceMetadata", "permalink"),
    ("salesforceMetadata", "objectLink"),
    ("notionMetadata", "privatePageLink"),
    ("m365TeamsMetadata", "channelWebURL"),
    ("m365OnedriveMetadata", "driveItemURL"),
)


class NightfallParser:

    """
    Parses a Nightfall AI violations export.

    Mirrors pkg/tools/nightfall/converter field for field so a file import and an API sync deduplicate
    against each other instead of producing two copies of everything.

    Nightfall splits a violation across two calls: the violation itself, and the detections that make
    it up, which carry the redacted evidence, the confidence and the API-key verdict. The evidence is
    what raises a violation to Critical and what names the credential in the title, so an export needs
    both - see extract().

    Nothing sensitive is imported. Nightfall only ever returns REDACTED detection text, and this parser
    reads that field and no other; there is no field in the API carrying the raw secret.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanType().
        return ["Nightfall AI - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Nightfall AI - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Nightfall AI violations export (JSON). Matches the scan type used by the "
            "Nightfall AI connector so file and API findings deduplicate. Include each violation's "
            "detections so findings carry their evidence and credential verdict."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Nightfall AI Parser.

        Mirrors the connector's ViolationToFinding:
        - title: "<what was found> exposed in <integration> (<location>)"; see title().
        - severity: the risk label, except that a verified live credential is always Critical.
        - description: the integration, location, policies, state, owner, file and exposure note,
          then the redacted detections.
        - mitigation: the connector's three remediation steps.
        - references: the resource link, the integration's own permalink and the file permalink.
        - severity_justification: Nightfall's numeric risk score and its source.
        - active / is_mitigated / out_of_scope / verified: from the violation state.
        - file_path / line: set for GitHub violations, which are the only ones with a code location.
        - service: the integration the violation was found in.
        - unique_id_from_tool: the violation id.
        - vuln_id_from_tool: the first policy that matched.
        """
        return [
            "title",
            "severity",
            "date",
            "description",
            "mitigation",
            "references",
            "severity_justification",
            "file_path",
            "line",
            "service",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "tags",
            "active",
            "is_mitigated",
            "out_of_scope",
            "verified",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Nightfall AI Parser.

        Copied from the Nightfall AI block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields.
        """
        return ["title", "severity", "description"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        violations, detections = self.extract(data)

        return [
            self.build_finding(violation, self.detections_for(violation, detections), test)
            for violation in violations
            if isinstance(violation, dict)
        ]

    def extract(self, data):
        """
        Return the violations and the detections belonging to each.

        Nightfall's violation list nests rows under "violations". The detections come from a second
        endpoint, one call per violation, and carry no violation id of their own, so an export keys
        them by violation id under "findings" (or "detections"), or nests them on each violation.
        """
        detections = {}
        violations = None

        if isinstance(data, list):
            violations = data
        elif isinstance(data, dict):
            for key in ("violations", "results"):
                if isinstance(data.get(key), list):
                    violations = data[key]
                    break
            for key in ("findings", "detections"):
                if isinstance(data.get(key), dict):
                    detections = {str(k): v for k, v in data[key].items() if isinstance(v, list)}
                    break

        if violations is None:
            msg = (
                "A Nightfall AI export is the violation-list response, a JSON object with a "
                f"'violations' list; got {type(data).__name__}."
            )
            raise TypeError(msg)
        return violations, detections

    def detections_for(self, violation, detections):
        """The detections nested on the violation, else the ones indexed by its id."""
        for key in ("findings", "detections"):
            nested = violation.get(key)
            if isinstance(nested, list):
                return [item for item in nested if isinstance(item, dict)]
            if isinstance(nested, dict) and isinstance(nested.get("findings"), list):
                return [item for item in nested["findings"] if isinstance(item, dict)]
        indexed = detections.get(str(violation.get("id")), [])
        return [item for item in indexed if isinstance(item, dict)]

    def build_finding(self, violation, detections, test):
        state = str(violation.get("state") or "").strip().upper()
        integration = str(violation.get("integration") or "").strip()

        finding = Finding(
            test=test,
            title=self.title(violation, detections, integration),
            severity=self.severity(violation, detections),
            date=self.date(violation),
            description=self.describe(violation, detections, integration),
            mitigation=self.mitigation(integration),
            references=self.references(violation),
            active=state in {STATE_ACTIVE, STATE_PENDING},
            is_mitigated=state == STATE_RESOLVED,
            # Nightfall expires a violation whose resource it can no longer see.
            out_of_scope=state == STATE_EXPIRED,
            # A pending violation has not been triaged yet, so it is not verified.
            verified=state not in {"", STATE_PENDING},
            # Nightfall inspects data at rest in a SaaS app, not a running application.
            static_finding=True,
            dynamic_finding=False,
            service=integration or None,
            unique_id_from_tool=str(violation.get("id")) if violation.get("id") else None,
            vuln_id_from_tool=self.first_policy(violation) or None,
        )
        finding.unsaved_tags = self.tags(violation, detections, integration)

        if file_path := self.file_path(violation):
            finding.file_path = file_path
        if line := self.line_number(detections):
            finding.line = line
        if (score := self.risk_score(violation)) > 0:
            finding.severity_justification = self.severity_justification(violation, score)
        return finding

    def title(self, violation, detections, integration):
        """
        "<what was found> exposed in <integration> (<location>)".

        The subject is the credential the detections identified, falling back to the policy that
        matched and then to a generic label - a violation is worth reporting even when Nightfall
        cannot say what kind of secret it saw.
        """
        subject = self.detected_subject(detections) or self.first_policy(violation) or "Sensitive data"
        label = self.integration_label(integration)
        location = self.location(violation)
        if location:
            return f"{subject} exposed in {label} ({location})"
        if label:
            return f"{subject} exposed in {label}"
        return f"{subject} exposed"

    def detected_subject(self, detections):
        """The kind of credential the first API-key detection identified."""
        for detection in detections:
            key = self.api_key(detection)
            if key is None:
                continue
            kind = str(key.get("kind") or "").strip()
            if not kind or kind.upper() == "UNSPECIFIED":
                kind = "API"
            if self.is_live(key):
                return f"Verified live {kind} credential"
            return f"{kind} credential"
        return ""

    def integration_label(self, integration):
        """Nightfall names integrations M365_TEAMS; the connector prints them M365 TEAMS."""
        return integration.replace("_", " ")

    def api_key(self, detection):
        metadata = detection.get("metadata")
        if not isinstance(metadata, dict):
            return None
        key = metadata.get("apiKeyMetaData")
        return key if isinstance(key, dict) else None

    def is_live(self, key):
        """
        Whether Nightfall could confirm the credential works.

        Either it authenticated with it, or it verified the key's signature.
        """
        if not isinstance(key, dict):
            return False
        return str(key.get("status") or "").strip().upper() in LIVE_KEY_STATUSES

    def severity(self, violation, detections):
        """
        Grade the violation.

        A credential Nightfall verified as live is Critical whatever the policy's risk says - it is a
        working secret in a place it should not be. Otherwise the risk label is used, and an
        unrecognised one is Info rather than a guess.
        """
        for detection in detections:
            if self.is_live(self.api_key(detection)):
                return "Critical"
        risk = str(violation.get("risk") or "").strip().upper()
        if not risk:
            return DEFAULT_SEVERITY
        return SEVERITY_BY_RISK.get(risk, DEFAULT_SEVERITY)

    def date(self, violation):
        """Nightfall sends the creation time as unix seconds."""
        created = violation.get("createdAt")
        if isinstance(created, int | float) and not isinstance(created, bool) and created > 0:
            with suppress(OSError, OverflowError, ValueError):
                return datetime.fromtimestamp(created, tz=UTC).date()
        return datetime.now(tz=UTC).date()

    def describe(self, violation, detections, integration):
        sections = []
        details = []

        def add(label, value):
            text = str(value).strip() if value is not None else ""
            if text:
                details.append(f"**{label}:** {text}")

        add("Integration", self.integration_label(integration))
        add("Location", self.location(violation))
        add("Policies", ", ".join(self.policy_names(violation)))
        add("Nightfall state", violation.get("state"))

        user_info = violation.get("userInfo")
        if isinstance(user_info, dict):
            add("Resource owner", self.first_non_empty(user_info.get("username"), user_info.get("userEmail")))

        file_details = violation.get("fileDetails")
        if isinstance(file_details, dict):
            add("File", file_details.get("fileName"))
            add("File type", file_details.get("mimeType"))

        add("Exposure", self.exposure_note(violation))

        if details:
            sections.append("\n".join(details))
        if evidence := self.evidence(detections):
            sections.append("**Redacted detections**\n" + evidence)
        return "\n\n".join(sections)

    def exposure_note(self, violation):
        """
        Why this violation is worse than a private one.

        Only three integrations report a sharing state that makes the exposure external.
        """
        metadata = violation.get("metadata")
        if not isinstance(metadata, dict):
            return ""
        gdrive = metadata.get("gdriveMetadata")
        if isinstance(gdrive, dict) and str(gdrive.get("permissionSetting") or "").strip():
            return "Drive permission " + str(gdrive["permissionSetting"]).strip()
        notion = metadata.get("notionMetadata")
        if isinstance(notion, dict) and notion.get("sharedExternally"):
            return "the Notion page is shared externally"
        github = metadata.get("githubMetadata")
        # An absent isRepoPrivate reads as public, matching the connector: a repository Nightfall did
        # not call private is treated as one it could not confirm was private.
        if isinstance(github, dict) and not github.get("isRepoPrivate"):
            return "the GitHub repository is public"
        return ""

    def evidence(self, detections):
        """
        One line per detection: the credential kind, the REDACTED value, the confidence and where it
        sat in the resource.

        Nightfall's API only ever returns redacted detection text, and that is the only text field
        read here, so no secret is imported.
        """
        lines = []
        for detection in detections:
            parts = []
            key = self.api_key(detection)
            if key is not None:
                descriptor = str(key.get("kind") or "").strip() + " key"
                if status := str(key.get("status") or "").strip():
                    descriptor += f" ({status})"
                parts.append(descriptor)
            if redacted := str(detection.get("redactedSensitiveText") or "").strip():
                parts.append(f"redacted value `{redacted}`")
            if confidence := str(detection.get("confidence") or "").strip():
                parts.append(f"confidence {confidence}")
            if location := self.detection_location(detection):
                parts.append(location)
            if parts:
                lines.append("- " + ", ".join(parts))
        return "\n".join(lines)

    def detection_location(self, detection):
        if sub := str(detection.get("subLocation") or "").strip():
            return sub
        if line := self.line(detection):
            return f"line {line}"
        return ""

    def line(self, detection):
        location = detection.get("redactedLocation")
        if not isinstance(location, dict):
            return 0
        line_range = location.get("lineRange")
        if not isinstance(line_range, dict):
            return 0
        start = line_range.get("start")
        if isinstance(start, int | float) and not isinstance(start, bool) and start > 0:
            return int(start)
        return 0

    def line_number(self, detections):
        """The first detection that knows which line it was on."""
        for detection in detections:
            if line := self.line(detection):
                return line
        return 0

    def mitigation(self, integration):
        """The connector's remediation steps, which are the same three for every integration."""
        return "\n".join([
            f"Remove or redact the sensitive data from the {self.integration_label(integration)} resource.",
            ("Rotate any credential that was exposed — assume it is compromised, whether or not "
             "Nightfall could verify it."),
            "Review who had access to the resource while the data was exposed.",
        ])

    def references(self, violation):
        """The resource link, the integration's own permalink and the file permalink, deduplicated."""
        file_details = violation.get("fileDetails")
        permalink = file_details.get("permalink") if isinstance(file_details, dict) else ""

        links = []
        for link in (violation.get("resourceLink"), self.link(violation), permalink):
            trimmed = str(link or "").strip()
            if trimmed and trimmed not in links:
                links.append(trimmed)
        return "\n".join(links)

    def location(self, violation):
        """
        Where in the SaaS app the data was found.

        Every integration nests its own metadata block under a different key and describes a location
        with different fields, so this is a table rather than a formula.
        """
        metadata = violation.get("metadata")
        if not isinstance(metadata, dict):
            return ""
        for key, separator, fields in LOCATION_BY_INTEGRATION:
            block = metadata.get(key)
            if not isinstance(block, dict):
                continue
            parts = [str(block.get(field) or "").strip() for field in fields]
            if key == "zendeskMetadata":
                parts[1] = self.ticket_reference(parts[1])
            joined = separator.join(part for part in parts if part)
            if key == "githubMetadata":
                joined += self.path_suffix(block.get("filePath"))
            return joined
        return ""

    def link(self, violation):
        metadata = violation.get("metadata")
        if not isinstance(metadata, dict):
            return ""
        for key, field in LINK_BY_INTEGRATION:
            block = metadata.get(key)
            if isinstance(block, dict):
                return str(block.get(field) or "").strip()
        return ""

    def ticket_reference(self, ticket_id):
        """A numeric Zendesk ticket id is rendered as #123; a non-numeric one is left alone."""
        if not ticket_id:
            return ""
        return f"#{ticket_id}" if ticket_id.isdigit() else ticket_id

    def path_suffix(self, path):
        trimmed = str(path or "").strip()
        return f":{trimmed}" if trimmed else ""

    def file_path(self, violation):
        """Only a GitHub violation has a path in a repository."""
        metadata = violation.get("metadata")
        if not isinstance(metadata, dict):
            return ""
        github = metadata.get("githubMetadata")
        if not isinstance(github, dict):
            return ""
        return str(github.get("filePath") or "").strip()

    def policy_names(self, violation):
        names = violation.get("policyNames")
        if not isinstance(names, list):
            return []
        return [str(name).strip() for name in names if str(name or "").strip()]

    def first_policy(self, violation):
        names = self.policy_names(violation)
        return names[0] if names else ""

    def risk_score(self, violation):
        score = violation.get("riskScore")
        if isinstance(score, int | float) and not isinstance(score, bool):
            return float(score)
        return 0.0

    def severity_justification(self, violation, score):
        justification = f"Nightfall risk score: {self.render_score(score)}"
        if source := str(violation.get("riskSource") or "").strip():
            justification += f" (source: {source})"
        return justification

    def render_score(self, score):
        """Render the score the way the connector does - 8.5 stays 8.5, but 9.0 prints as 9."""
        return str(int(score)) if score == int(score) else repr(score)

    def tags(self, violation, detections, integration):
        tags = ["dlp"]
        tags.extend(value for value in (integration, str(violation.get("risk") or "").strip()) if value)
        for detection in detections:
            key = self.api_key(detection)
            if key is None:
                continue
            kind = str(key.get("kind") or "").strip()
            if kind and kind not in tags:
                tags.append(kind)
        return tags

    def first_non_empty(self, *values):
        for value in values:
            trimmed = str(value or "").strip()
            if trimmed:
                return trimmed
        return ""
