import json
import re
from contextlib import suppress

from dojo.models import Finding

# DTP's own scale, where 1 is the MOST severe and 5 is informational.
SEVERITY_BY_CODE = {1: "Critical", 2: "High", 3: "Medium", 4: "Low"}
DEFAULT_SEVERITY = "Info"

# The advisory identifiers the connector's shared extractor recognises in free text.
VULNERABILITY_ID_PATTERN = re.compile(
    r"CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|GO-\d{4}-\d+|RHSA-\d{4}:\d+",
)


class ParasoftParser:

    """
    Parses a Parasoft DTP static-analysis violations export.

    Mirrors pkg/tools/parasoft/connector/finding_converter field for field so a file import and an API
    sync deduplicate against each other instead of producing two copies of everything.

    DTP grades with a numeric severity where 1 is the MOST severe - the inverse of a score - so reading
    it as one would invert the whole ladder; see severity().
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName. Note it does NOT follow the
        # "<Vendor> - Connectors Import" pattern, so it cannot be derived - it has to be copied.
        return ["Parasoft DTP Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Parasoft DTP Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Parasoft DTP static-analysis violations export (JSON). Matches the scan type used "
            "by the Parasoft connector so file and API findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Parasoft Parser.

        Mirrors the connector's Convert:
        - title: "<rule>: <message>", or whichever of the two is present.
        - severity: DTP's numeric severity, where 1 is the most severe; see severity().
        - description: the message, rule, category, analyzer and language.
        - file_path / line: where DTP found the violation.
        - vuln_id_from_tool: the rule id, which is DTP's rule identity.
        - unique_id_from_tool: "parasoft-<hash>", then the violation id, then rule plus file.
        """
        return [
            "title",
            "severity",
            "description",
            "file_path",
            "line",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "unsaved_vulnerability_ids",
            "tags",
            "active",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Parasoft Parser.

        Copied from the Parasoft block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. The file path and the rule are both in
        the hash: the same rule firing in two files is two violations to fix.
        """
        return ["title", "severity", "file_path", "vuln_id_from_tool"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        return [self.build_finding(row, test) for row in self.rows(data)]

    def rows(self, data):
        """
        Return the violations in the export.

        DTP answers {"staticAnalysisViolations": [...]}, so that is the shape a saved export has. A
        bare array is accepted too.
        """
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
        if isinstance(data, dict):
            for key in ("staticAnalysisViolations", "violations", "data", "results"):
                if isinstance(data.get(key), list):
                    return [row for row in data[key] if isinstance(row, dict)]

        msg = (
            "A Parasoft export is the violations response, a JSON object with a "
            f"'staticAnalysisViolations' list; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def build_finding(self, row, test):
        rule = str(row.get("rule") or "")
        message = str(row.get("message") or "")

        finding = Finding(
            test=test,
            title=self.title(rule, message),
            severity=self.severity(row),
            description=self.describe(row, rule, message),
            file_path=str(row.get("locFile") or "") or None,
            line=self.integer(row.get("locStartLine")) or None,
            unique_id_from_tool=self.unique_id(row, rule),
            vuln_id_from_tool=rule or None,
            # DTP analyses source; nothing is exercised.
            static_finding=True,
            dynamic_finding=False,
            active=True,
        )
        finding.unsaved_tags = self.tags(row)

        if identifiers := self.vulnerability_ids(rule, message):
            finding.unsaved_vulnerability_ids = identifiers
        return finding

    def unique_id(self, row, rule):
        """
        DTP's own violation hash, then its id, then the rule and the file.

        The hash is what stays stable as a file is edited around the violation, which is why it is
        preferred - the rule-plus-file fallback would merge two violations of one rule in one file.
        """
        for key in ("hash", "id"):
            if value := str(row.get(key) or ""):
                return f"parasoft-{value}"
        return f"parasoft-{rule}-{row.get('locFile') or ''}"

    def title(self, rule, message):
        if rule and message:
            return f"{rule}: {message}"
        if message:
            return message
        if rule:
            return rule
        return "Parasoft DTP violation"

    def severity(self, row):
        """
        DTP's numeric severity, where 1 is the MOST severe and 5 is informational.

        This is the inverse of a score: reading it as one would invert the entire ladder. Severity 5,
        0 and anything unrecognised are Info.
        """
        return SEVERITY_BY_CODE.get(self.integer(row.get("severity")), DEFAULT_SEVERITY)

    def describe(self, row, rule, message):
        lines = []

        def write(label, value):
            # The connector tests for emptiness WITHOUT trimming, which a plain truthiness test
            # reproduces exactly for strings.
            if value:
                lines.append(f"**{label}:** {value}")

        write("Message", message)
        write("Rule", rule)
        write("Category", str(row.get("ruleCategory") or ""))
        write("Analyzer", str(row.get("analyzerId") or ""))
        write("Language", str(row.get("language") or ""))
        return "\n".join(lines).strip()

    def tags(self, row):
        """The rule, category, analyzer and language, for filtering."""
        return [
            value
            for value in (
                str(row.get(key) or "").strip()
                for key in ("rule", "ruleCategory", "analyzerId", "language")
            )
            if value
        ]

    def vulnerability_ids(self, rule, message):
        """
        Any advisory identifier named in the rule id or the message.

        Rare for static analysis, but cheap - and a rule that names a CVE is worth linking. The
        connector's shared extractor sorts its results and drops case-insensitive duplicates.
        """
        matches = sorted(VULNERABILITY_ID_PATTERN.findall(f"{rule} {message}"))
        identifiers = []
        for match in matches:
            # Adjacent-only dedupe after the sort, which is what slices.CompactFunc does.
            if not identifiers or identifiers[-1].lower() != match.lower():
                identifiers.append(match)
        return identifiers

    def integer(self, value):
        """DTP's numbers may arrive as JSON numbers or quoted strings."""
        if isinstance(value, bool) or value is None:
            return 0
        if isinstance(value, int | float):
            return int(value)
        if isinstance(value, str):
            with suppress(ValueError):
                return int(float(value.strip() or 0))
        return 0
