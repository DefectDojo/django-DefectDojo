import json
import re
from contextlib import suppress
from datetime import UTC, datetime

from dojo.models import Finding

SEVERITY_BY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
DEFAULT_SEVERITY = "Info"

# Datadog statuses that mean the finding is not actionable.
IGNORED_STATUSES = {"muted", "resolved", "auto_closed"}

# Finding types that describe something observed at runtime rather than read from a configuration or
# an inventory. Everything else is static.
DYNAMIC_FINDING_TYPES = {
    "runtime_code_vulnerability",
    "api_security",
    "attack_path",
    "workload_activity",
    "identity_risk",
}

# The advisory identifiers the connector's shared extractor recognises in free text.
VULNERABILITY_ID_PATTERN = re.compile(
    r"CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|GO-\d{4}-\d+|RHSA-\d{4}:\d+",
)


class DatadogParser:

    """
    Parses a Datadog Cloud Security findings export.

    Mirrors pkg/tools/datadog/connector/finding_converter field for field so a file import and an API
    sync deduplicate against each other instead of producing two copies of everything.

    Datadog returns one endpoint for everything it calls a security finding - misconfigurations, code
    and library vulnerabilities, attack paths, identity risks - distinguished by finding_type. That
    single stream is why the same parser has to decide static versus dynamic per row rather than for
    the file as a whole; see build_finding().
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName. Note it does NOT follow the
        # "<Vendor> - Connectors Import" pattern, so it cannot be derived - it has to be copied.
        return ["Datadog Cloud Security"]

    def get_label_for_scan_types(self, scan_type):
        return "Datadog Cloud Security"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Datadog Cloud Security findings export (JSON), the /api/v2/posture_management/"
            "findings response. Matches the scan type used by the Datadog connector so file and API "
            "findings deduplicate. Muted, resolved and passing findings are skipped."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Datadog Parser.

        Mirrors the connector's Convert:
        - title: the finding title, then the rule name, then the finding type.
        - severity: Datadog's own severity label; anything unrecognised is Info.
        - description: an Overview section, then the rule, finding type, resource, compliance
          evaluation and advisory as bullets.
        - date: when Datadog first saw the finding (unix milliseconds).
        - cvssv3 / cvssv3_score: the base severity details, falling back to the adjusted ones.
        - component_name / component_version: the affected package, for library findings.
        - service: read out of Datadog's own "service:" tag.
        - unique_id_from_tool: the finding's id.
        """
        return [
            "title",
            "severity",
            "date",
            "description",
            "cvssv3",
            "cvssv3_score",
            "component_name",
            "component_version",
            "service",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "unsaved_vulnerability_ids",
            "tags",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Datadog Parser.

        Copied from the Datadog block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields.
        """
        return ["title", "severity", "component_name"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        findings = []
        for row in self.rows(data):
            attributes = self.attributes(row)
            if attributes is None or self.ignored(attributes):
                continue
            findings.append(self.build_finding(row, attributes, test))
        return findings

    def rows(self, data):
        """
        Return the findings in the export.

        Datadog's findings response nests them under "data"; a bare array is accepted too.
        """
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
        if isinstance(data, dict):
            if isinstance(data.get("data"), list):
                return [row for row in data["data"] if isinstance(row, dict)]
            if "attributes" in data:
                return [data]

        msg = (
            "A Datadog Cloud Security export is the findings response, a JSON object with a 'data' "
            f"list; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def envelope(self, row):
        value = row.get("attributes")
        return value if isinstance(value, dict) else {}

    def attributes(self, row):
        """
        The finding's own attributes.

        Datadog nests them twice - attributes.attributes - because the outer object also carries the
        row's tags and timestamp.
        """
        inner = self.envelope(row).get("attributes")
        return inner if isinstance(inner, dict) else None

    def block(self, attributes, key):
        value = attributes.get(key)
        return value if isinstance(value, dict) else {}

    def strings(self, value):
        if isinstance(value, str):
            return [value.strip()] if value.strip() else []
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item or "").strip()]
        return []

    def ignored(self, attributes):
        """
        Whether Datadog has already dealt with this finding.

        Three separate ways it says so, and all three have to be honoured or a triaged queue comes
        back: the status, an explicit workflow mute, and - for a compliance rule - an evaluation that
        passed. A passing rule is the tool reporting that nothing is wrong.
        """
        if str(attributes.get("status") or "").strip().lower() in IGNORED_STATUSES:
            return True
        mute = self.block(self.block(attributes, "workflow"), "mute")
        if mute.get("is_muted") is True:
            return True
        evaluation = str(self.block(attributes, "compliance").get("evaluation") or "").strip()
        return evaluation.lower() == "pass"

    def build_finding(self, row, attributes, test):
        finding_type = str(attributes.get("finding_type") or "").strip()
        # A runtime finding is something Datadog watched happen; everything else it read.
        static = finding_type.lower() not in DYNAMIC_FINDING_TYPES

        finding = Finding(
            test=test,
            title=self.title(attributes, finding_type),
            severity=self.severity(attributes),
            description=self.describe(attributes, finding_type),
            unique_id_from_tool=self.unique_id(row, attributes),
            static_finding=static,
            dynamic_finding=not static,
        )
        finding.unsaved_tags = self.tags(row, attributes, finding_type)

        if date := self.date(attributes):
            finding.date = date
        if rule_id := str(self.block(attributes, "rule").get("id") or "").strip():
            finding.vuln_id_from_tool = rule_id
        if identifiers := self.vulnerability_ids(attributes):
            finding.unsaved_vulnerability_ids = identifiers

        vector, score = self.cvss(attributes)
        if vector or score > 0:
            finding.cvssv3 = vector
            finding.cvssv3_score = score

        package = self.block(attributes, "package")
        if package:
            finding.component_name = str(package.get("name") or "").strip() or None
            finding.component_version = str(package.get("version") or "").strip() or None
        if service := self.tag_value(self.strings(self.envelope(row).get("tags")), "service"):
            finding.service = service
        return finding

    def unique_id(self, row, attributes):
        """The row's id, falling back to the finding id Datadog repeats inside the attributes."""
        if identifier := str(row.get("id") or "").strip():
            return identifier
        return str(attributes.get("finding_id") or "").strip() or None

    def title(self, attributes, finding_type):
        if title := str(attributes.get("title") or "").strip():
            return title
        if name := str(self.block(attributes, "rule").get("name") or "").strip():
            return name
        if finding_type:
            return f"Datadog finding: {finding_type}"
        return "Datadog security finding"

    def severity(self, attributes):
        """
        Datadog's own severity label.

        Note base_severity is deliberately NOT consulted: it is the rule's default before Datadog
        adjusts for the environment, and the adjusted value is the one worth importing.
        """
        label = str(attributes.get("severity") or "").strip().lower()
        return SEVERITY_BY_LABEL.get(label, DEFAULT_SEVERITY)

    def date(self, attributes):
        """Datadog timestamps these in unix MILLIseconds, not seconds."""
        for key in ("first_seen_at", "detection_changed_at"):
            value = attributes.get(key)
            if isinstance(value, int | float) and not isinstance(value, bool) and value > 0:
                with suppress(OSError, OverflowError, ValueError):
                    return datetime.fromtimestamp(value / 1000, tz=UTC).date()
        return None

    def describe(self, attributes, finding_type):
        """
        The connector's shared formatter: a level-2 heading, then prefixed bullets.

        Reproduced exactly - a "## Overview" heading followed by a blank line, then "* **Rule:** ..."
        lines - so the two import paths do not differ for no reason.
        """
        parts = []
        if description := str(attributes.get("description") or "").strip():
            parts.append("## Overview\n\n" + description + "\n")

        bullets = []

        def add(prefix, value):
            text = str(value or "").strip()
            if text:
                bullets.append(f"* **{prefix}** {text}")

        add("Rule:", self.block(attributes, "rule").get("name"))
        add("Finding type:", finding_type)
        add("Resource:", self.resource_label(attributes))
        add("Compliance evaluation:", self.block(attributes, "compliance").get("evaluation"))
        advisory = self.block(attributes, "advisory")
        add("Advisory:", advisory.get("cve"))
        add("Advisory summary:", advisory.get("summary"))

        if bullets:
            parts.append("\n".join(bullets) + "\n")
        return "".join(parts).rstrip("\n") + "\n" if parts else ""

    def resource_label(self, attributes):
        """"<name> (<type>)" - the resource name, falling back to its id."""
        name = str(attributes.get("resource_name") or "").strip()
        if not name:
            name = str(attributes.get("resource_id") or "").strip()
        if not name:
            return ""
        kind = str(attributes.get("resource_type") or "").strip()
        return f"{name} ({kind})" if kind else name

    def vulnerability_ids(self, attributes):
        """
        The advisory's CVE and aliases, then any identifier in the title or description.

        Datadog names the CVE in the prose for some finding types and only in the advisory object for
        others, so both are read. Order is preserved and duplicates dropped, as the connector does.
        """
        advisory = self.block(attributes, "advisory")
        candidates = [str(advisory.get("cve") or "")]
        candidates.extend(self.strings(advisory.get("aliases")))
        prose = "|".join([str(attributes.get("title") or ""), str(attributes.get("description") or "")])
        candidates.extend(VULNERABILITY_ID_PATTERN.findall(prose))

        identifiers = []
        for candidate in candidates:
            trimmed = candidate.strip()
            if trimmed and trimmed not in identifiers:
                identifiers.append(trimmed)
        return identifiers

    def cvss(self, attributes):
        """
        The base severity details, falling back to the adjusted ones.

        The first block carrying either a vector or a positive score wins, and both of its values are
        taken together - mixing a vector from one with a score from the other would describe a
        scoring that never existed.
        """
        details = self.block(attributes, "severity_details")
        for key in ("base", "adjusted"):
            detail = self.block(details, key)
            if not detail:
                continue
            vector = str(detail.get("vector") or "").strip()
            score = detail.get("score")
            score = float(score) if isinstance(score, int | float) and not isinstance(score, bool) else 0.0
            if vector or score > 0:
                return vector, score
        return "", 0.0

    def tags(self, row, attributes, finding_type):
        """
        Datadog's own tags, prefixed context, and the resource's cloud placement.

        Deduplicated but NOT sorted: the connector preserves the order it built them in, and a tag
        list that reorders on every sync reads as a change.
        """
        ordered = ["datadog"]
        if finding_type:
            ordered.append(f"finding_type:{finding_type}")

        resource = self.block(attributes, "cloud_resource")
        if provider := str(resource.get("cloud_provider") or "").strip():
            ordered.append(f"cloud_provider:{provider.lower()}")
        if region := str(resource.get("region") or "").strip():
            ordered.append(f"region:{region}")
        if account := str(self.block(resource, "account").get("account_id") or "").strip():
            ordered.append(f"account:{account}")

        if resource_type := str(attributes.get("resource_type") or "").strip():
            ordered.append(f"resource_type:{resource_type}")
        ordered.extend(self.strings(self.envelope(row).get("tags")))

        deduped = []
        for tag in ordered:
            trimmed = tag.strip()
            if trimmed and trimmed not in deduped:
                deduped.append(trimmed)
        return deduped

    def tag_value(self, tags, key):
        """Datadog writes its metadata as "key:value" tags."""
        prefix = f"{key}:"
        for tag in tags:
            if tag.startswith(prefix):
                return tag[len(prefix):]
        return ""
