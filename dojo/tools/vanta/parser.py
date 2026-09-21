import json
from contextlib import suppress
from datetime import datetime

from dojo.models import Finding

# Vanta grades nothing: a compliance test either passes or fails. The connector imports every failing
# entity at Medium rather than inventing a scale the tool does not have.
DEFAULT_SEVERITY = "Medium"

# The entity status the connector asks Vanta for.
ENTITY_STATUS_FAILING = "FAILING"


class VantaParser:

    """
    Parses a Vanta compliance export.

    Mirrors pkg/tools/vanta/connector/finding_converter field for field so a file import and an API
    sync deduplicate against each other instead of producing two copies of everything.

    A Vanta finding is a (test, failing entity) pair: the test is the control - "MFA is enabled" - and
    the entity is the resource failing it. The failing entities come from a second call per test, so an
    export needs both; see extract().
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName. Note it does NOT follow the
        # "<Vendor> - Connectors Import" pattern, so it cannot be derived - it has to be copied.
        return ["Vanta Compliance"]

    def get_label_for_scan_types(self, scan_type):
        return "Vanta Compliance"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Vanta compliance export (JSON). Matches the scan type used by the Vanta "
            "connector so file and API findings deduplicate. Include each test's failing entities - "
            "the failing entity is the finding."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Vanta Parser.

        Mirrors the connector's Convert:
        - title: the test's name, else "Vanta test <id>".
        - severity: always Medium; Vanta has no severity scale. See severity().
        - description: the failing resource and its type, the category, the integrations, then the
          test's description and why it failed.
        - mitigation: the test's remediation description.
        - component_name: the failing entity, so two resources failing one test stay apart.
        - unique_id_from_tool: "vanta-<test id>-<entity id>".
        - vuln_id_from_tool: the test id, which is the control.
        """
        return [
            "title",
            "severity",
            "date",
            "description",
            "mitigation",
            "component_name",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "tags",
            "active",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Vanta Parser.

        Copied from the Vanta block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. The component - the failing entity -
        is what keeps two resources failing the same control from merging into one finding, which
        matters here because every finding shares the same severity.
        """
        return ["title", "severity", "component_name"]

    def get_findings(self, filename, test_object):
        data = json.load(filename)
        tests, entities = self.extract(data)

        findings = []
        for test in tests:
            if not isinstance(test, dict):
                continue
            findings.extend(
                self.finding(test, entity, test_object)
                for entity in self.entities_for(test, entities)
            )
        return findings

    def extract(self, data):
        """
        Return the tests and the failing entities of each.

        Vanta's tests response nests rows under results.data. The failing entities come from a second
        call per test and carry no test id of their own, so an export keys them by test id or nests
        them on the test.
        """
        entities = {}
        tests = None

        if isinstance(data, list):
            tests = data
        elif isinstance(data, dict):
            tests = self.rows(data, ("tests",))
            entities = self.index_entities(data)

        if tests is None:
            msg = (
                "A Vanta export is the tests response, a JSON object with results.data rows; got "
                f"{type(data).__name__}."
            )
            raise TypeError(msg)
        return tests, entities

    def rows(self, source, keys):
        """
        Vanta wraps every list as {"results": {"data": [...]}}.

        A bare list under the named key, or a plain list, is accepted too.
        """
        results = source.get("results")
        if isinstance(results, dict) and isinstance(results.get("data"), list):
            return [row for row in results["data"] if isinstance(row, dict)]
        for key in keys:
            value = source.get(key)
            if isinstance(value, list):
                return [row for row in value if isinstance(row, dict)]
            if isinstance(value, dict):
                nested = value.get("results")
                if isinstance(nested, dict) and isinstance(nested.get("data"), list):
                    return [row for row in nested["data"] if isinstance(row, dict)]
        return None

    def index_entities(self, data):
        """The failing entities as a map keyed by test id."""
        for key in ("entities", "failing_entities"):
            source = data.get(key)
            if not isinstance(source, dict):
                continue
            indexed = {}
            for test_id, value in source.items():
                rows = self.rows({"entities": value}, ("entities",))
                if rows is None and isinstance(value, list):
                    rows = [row for row in value if isinstance(row, dict)]
                if rows is not None:
                    indexed[str(test_id)] = rows
            return indexed
        return {}

    def entities_for(self, test, entities):
        """
        The failing entities nested on the test, else those indexed by its id.

        Only entities Vanta reports as FAILING are findings - a passing one is the control working.
        The connector asks Vanta for the failing ones specifically, so an export that carries every
        entity is filtered here instead.
        """
        rows = self.rows(test, ("entities", "failing_entities"))
        if rows is None:
            rows = entities.get(str(test.get("id")), [])
        return [row for row in rows if self.is_failing(row)]

    def is_failing(self, entity):
        status = str(entity.get("entityStatus") or "").strip().upper()
        return status in {"", ENTITY_STATUS_FAILING}

    def finding(self, test, entity, test_object):
        finding = Finding(
            test=test_object,
            title=self.title(test),
            severity=self.severity(),
            description=self.describe(test, entity),
            mitigation=str(test.get("remediationDescription") or ""),
            component_name=str(entity.get("displayName") or "") or None,
            unique_id_from_tool=f"vanta-{test.get('id') or ''}-{entity.get('id') or ''}",
            vuln_id_from_tool=str(test.get("id") or "") or None,
            # Vanta evaluates configuration and records, not a running request.
            static_finding=True,
            dynamic_finding=False,
            # A failing entity is currently failing; that is what makes it a finding.
            active=True,
        )
        finding.unsaved_tags = self.tags(test, entity)
        if date := self.date(test, entity):
            finding.date = date
        return finding

    def severity(self):
        """
        Always Medium.

        Vanta has no severity scale - a compliance test passes or fails - so the connector grades
        every failing entity the same rather than inventing a ladder. Info would read as
        non-actionable, and a failing control is actionable by definition.
        """
        return DEFAULT_SEVERITY

    def title(self, test):
        if name := str(test.get("name") or ""):
            return name
        return f"Vanta test {test.get('id') or ''}"

    def describe(self, test, entity):
        """
        The failing resource and context as single-newline fields, then the prose sections.

        The prose is separated by a blank line because it is paragraphs rather than fields - the
        connector's own distinction.
        """
        lines = []
        for label, value in (
            ("Failing resource", entity.get("displayName")),
            ("Resource type", entity.get("responseType")),
            ("Category", test.get("category")),
        ):
            text = str(value or "")
            if text:
                lines.append(f"**{label}:** {text}")

        integrations = [str(item) for item in test.get("integrations") or [] if str(item or "")]
        if integrations:
            lines.append("**Integrations:** " + ", ".join(integrations))
        text = "\n".join(lines)

        for label, key in (("Description", "description"), ("Why this failed", "failureDescription")):
            value = str(test.get(key) or "")
            if not value:
                continue
            if text:
                text += "\n\n"
            text += f"**{label}:**\n{value}"
        return text.strip()

    def tags(self, test, entity):
        tags = ["compliance"]
        if category := str(test.get("category") or ""):
            tags.append(category)
        tags.extend(str(item) for item in test.get("integrations") or [] if str(item or ""))
        if response_type := str(entity.get("responseType") or ""):
            tags.append(response_type)
        return tags

    def date(self, test, entity):
        """
        When the entity started failing, falling back to when the test last flipped.

        The entity's own date is preferred because one control can have been failing for a year while
        a resource added last week has only just started failing it.
        """
        for value in (entity.get("createdDate"), test.get("latestFlipDate")):
            timestamp = str(value or "").strip()
            if not timestamp:
                continue
            with suppress(ValueError):
                return datetime.strptime(timestamp.split("T")[0], "%Y-%m-%d").date()
        return None
