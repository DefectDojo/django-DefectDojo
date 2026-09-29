import json
from contextlib import suppress
from datetime import UTC, datetime

from dojo.models import Finding

# Klocwork's severity CODE, 1 the most severe. Codes 5-10 are its informational tiers.
SEVERITY_BY_CODE = {1: "Critical", 2: "High", 3: "Medium", 4: "Low"}
DEFAULT_SEVERITY = "Info"

# Statuses that mean a reviewer decided the issue is not a real problem.
FALSE_POSITIVE_STATUSES = {"ignore", "not a problem", "filter"}


class KlocworkParser:

    """
    Parses a Klocwork issue export.

    Mirrors pkg/tools/klocwork/connector/finding_converter field for field so a file import and an API
    sync deduplicate against each other instead of producing two copies of everything.

    Klocwork's search endpoint answers with NDJSON - one JSON object per line, not an array - so that is
    the shape a saved export has, and it is what this parser reads first; see issues().
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName. Note it does NOT follow the
        # "<Vendor> - Connectors Import" pattern, so it cannot be derived - it has to be copied.
        return ["Klocwork Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Klocwork Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Klocwork issue export. Klocwork's search endpoint answers with NDJSON - one "
            "issue per line - and that shape is read first; a JSON array is accepted too. Matches the "
            "scan type used by the Klocwork connector so file and API findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Klocwork Parser.

        Mirrors the connector's Convert:
        - title: "<checker>: <name>", falling back to either alone, then the issue id.
        - severity: Klocwork's severity CODE, where 1 is the most severe; see severity().
        - description: the message, checker, method, taxonomy and status.
        - file_path / line: where Klocwork found it - the file path is in the deduplication hash.
        - references: the issue's own Klocwork URL.
        - active / false_p: from the status; see false_positive().
        - unique_id_from_tool: "klocwork-<id>".
        - vuln_id_from_tool: the checker code, which is Klocwork's rule identity.
        """
        return [
            "title",
            "severity",
            "date",
            "description",
            "references",
            "file_path",
            "line",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "tags",
            "active",
            "false_p",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Klocwork Parser.

        Copied from the Klocwork block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. The file path and the checker are both
        in the hash: the same checker firing in two files is two findings.
        """
        return ["title", "severity", "file_path", "vuln_id_from_tool"]

    def get_findings(self, filename, test):
        rows = self.issues(filename)
        findings = []
        for row in rows:
            if self.flex_int(row.get("id")) == 0:
                # The connector drops a row with no id: the id is the whole identity.
                continue
            findings.append(self.build_finding(row, test))
        return findings

    def issues(self, filename):
        """
        Return the issues in the export.

        Klocwork answers with NDJSON, so each line is parsed on its own. A line that is not an object,
        or that carries the run "summary" rather than an issue, is skipped - exactly as the connector's
        decoder does. A whole-document JSON array or an object with an "issues" list is accepted too,
        for an export somebody has already reshaped.
        """
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        with suppress(ValueError):
            data = json.loads(content)
            if isinstance(data, list):
                return [row for row in data if isinstance(row, dict)]
            if isinstance(data, dict):
                for key in ("issues", "results"):
                    if isinstance(data.get(key), list):
                        return [row for row in data[key] if isinstance(row, dict)]
                # A single issue object.
                if "id" in data:
                    return [data]
                # A search that matched nothing answers with the summary line alone, which is a valid
                # JSON document on its own. That is an empty result, not a malformed file - the same
                # rule the NDJSON path applies line by line.
                if "summary" in data:
                    return []
                msg = (
                    "A Klocwork export is the search response - NDJSON, one issue per line - or a "
                    "JSON array of issues; this object carries neither an 'issues' list nor an id."
                )
                raise TypeError(msg)

        rows = []
        for line in content.split("\n"):
            stripped = line.strip()
            # The summary line reports the run rather than an issue, and the connector skips it by
            # this same test rather than by parsing it.
            if not stripped.startswith("{") or '"summary"' in stripped:
                continue
            with suppress(ValueError):
                row = json.loads(stripped)
                if isinstance(row, dict):
                    rows.append(row)

        if not rows and content.strip():
            msg = (
                "A Klocwork export is the search response - NDJSON, one issue per line - or a JSON "
                "array of issues; no issue line was found."
            )
            raise TypeError(msg)
        return rows

    def build_finding(self, row, test):
        false_positive = self.false_positive(row)

        finding = Finding(
            test=test,
            title=self.title(row),
            severity=self.severity(row),
            description=self.describe(row),
            file_path=str(row.get("file") or "") or None,
            line=self.flex_int(row.get("line")) or None,
            unique_id_from_tool=f"klocwork-{self.flex_int(row.get('id'))}",
            vuln_id_from_tool=str(row.get("code") or "") or None,
            # Klocwork analyses source; nothing is exercised.
            static_finding=True,
            dynamic_finding=False,
            active=not false_positive,
            false_p=false_positive,
        )
        finding.unsaved_tags = self.tags(row)

        if url := str(row.get("url") or ""):
            finding.references = url
        if date := self.date(row):
            finding.date = date
        return finding

    def title(self, row):
        """"<checker>: <name>" - the checker alone is opaque, the name alone is not searchable."""
        name = str(row.get("name") or "")
        code = str(row.get("code") or "")
        if name and code:
            return f"{code}: {name}"
        if name:
            return name
        if code:
            return code
        return f"Klocwork issue {self.flex_int(row.get('id'))}"

    def severity(self, row):
        """
        Grade Klocwork's severity CODE, where 1 is the most severe.

        This is the inverse of a score: reading it as one would inverte the whole ladder. Codes 5-10
        are Klocwork's informational tiers and all become Info, as does an absent code.
        """
        return SEVERITY_BY_CODE.get(self.flex_int(row.get("severityCode")), DEFAULT_SEVERITY)

    def false_positive(self, row):
        """
        Klocwork records triage in the status.

        "Ignore", "Not a problem" and "Filter" are all a reviewer saying it is not real, so they are
        false positives and inactive. Everything else - including the deferred states the connector's
        query selects - stays active.
        """
        return str(row.get("status") or "").strip().lower() in FALSE_POSITIVE_STATUSES

    def describe(self, row):
        lines = []
        for label, key in (("Message", "message"), ("Checker", "code"), ("Method", "method"),
                           ("Taxonomy", "taxonomyName"), ("Status", "status")):
            value = str(row.get(key) or "")
            if value:
                lines.append(f"**{label}:** {value}")
        return "\n".join(lines)

    def tags(self, row):
        tags = []
        for key in ("taxonomyName", "code", "severity"):
            value = str(row.get(key) or "").strip()
            if value:
                tags.append(value)
        return tags

    def date(self, row):
        """Klocwork timestamps in unix MILLIseconds."""
        value = self.flex_int(row.get("dateOriginated"))
        if value <= 0:
            return None
        with suppress(OSError, OverflowError, ValueError):
            return datetime.fromtimestamp(value / 1000, tz=UTC).date()
        return None

    def flex_int(self, value):
        """
        Klocwork may send a number as a JSON number or a quoted string.

        The connector models both because its own decoder silently skips a line it cannot parse - so a
        server quoting its numerics would produce a clean, empty sync rather than an error.
        """
        if isinstance(value, bool) or value is None:
            return 0
        if isinstance(value, int | float):
            return int(value)
        if isinstance(value, str):
            with suppress(ValueError):
                return int(float(value.strip() or 0))
        return 0
