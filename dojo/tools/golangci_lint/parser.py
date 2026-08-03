import json
import re

from dojo.models import Finding

# golangci-lint aggregates around a hundred linters, and nearly all of them report style or
# correctness opinions rather than security weaknesses. Only these report a security weakness:
#   gosec    - the Go security checker (G-numbered rules: weak crypto, command injection, ...)
#   bidichk  - dangerous bidirectional Unicode, i.e. the "Trojan Source" class
# Resource-leak and error-handling linters (bodyclose, sqlclosecheck, rowserrcheck, errcheck,
# noctx) are deliberately excluded: they find bugs, not weaknesses, and importing them would bury
# real security findings under lint output.
SECURITY_LINTERS = frozenset({"gosec", "bidichk"})

# golangci-lint v2 passes gosec's own low/medium/high through in the Severity field. A
# golangci-lint `severity` config block can rewrite these to error/warning/info, so both
# vocabularies are mapped.
SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "error": "High",
    "medium": "Medium",
    "warning": "Medium",
    "low": "Low",
    "info": "Info",
}
# Everything imported here comes from a security linter, so an unrecognised or absent severity
# must not become Info - DefectDojo treats Info as non-actionable. gosec's own default severity is
# medium, so that is the fallback.
DEFAULT_SEVERITY = "Medium"

# gosec prefixes its message with the rule id, e.g. "G402: TLS InsecureSkipVerify set true."
# bidichk emits no rule id, so the id is optional.
RULE_ID = re.compile(r"^(?P<rule>[A-Z]+\d+):\s*(?P<message>.*)$", re.DOTALL)


class GolangciLintParser:

    """
    Parses a golangci-lint JSON report, importing only the security linters' findings.

    See SECURITY_LINTERS for what that means and why. Note that DefectDojo also ships a `gosec`
    parser for gosec's own JSON output; this parser exists because most Go projects run gosec
    through golangci-lint in CI and never produce a standalone gosec report.
    """

    def get_scan_types(self):
        return ["golangci-lint Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "golangci-lint Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import the security findings from a golangci-lint JSON report "
            "(`golangci-lint run --output.json.path report.json`). Only the gosec and bidichk "
            "linters are imported; the style and correctness linters are discarded."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the golangci-lint Parser.

        - title: the linter's own message, which for gosec leads with the rule id.
        - severity: gosec's low/medium/high, or a configured error/warning/info.
        - description: linter, rule, message and the offending source line.
        - file_path / line: from the issue's Pos block.
        - vuln_id_from_tool: the rule id (G402, ...) when the linter emits one.
        - static_finding: always true; golangci-lint analyses source.
        """
        return [
            "title",
            "severity",
            "description",
            "file_path",
            "line",
            "vuln_id_from_tool",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the golangci-lint Parser.

        golangci-lint issues carry no stable per-issue identifier, so this scan type is left on
        DefectDojo's default hashcode fields rather than being given an entry in
        HASHCODE_FIELDS_PER_SCANNER.
        """
        return ["title", "cwe", "line", "file_path", "description"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        if not isinstance(data, dict):
            msg = (
                "A golangci-lint report is a JSON object with an 'Issues' list; got "
                f"{type(data).__name__}. Produce one with --output.json.path."
            )
            raise TypeError(msg)

        # golangci-lint emits "Issues": [] for a clean run, and null in some older versions.
        issues = data.get("Issues") or []

        findings = []
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            if issue.get("FromLinter") not in SECURITY_LINTERS:
                continue
            findings.append(self.build_finding(issue, test))
        return findings

    def build_finding(self, issue, test):
        linter = issue.get("FromLinter") or ""
        text = (issue.get("Text") or "").strip()
        rule, message = self.split_rule(text)
        position = issue.get("Pos") or {}

        finding = Finding(
            test=test,
            title=text or f"{linter} finding",
            severity=self.severity(issue),
            description=self.describe(linter, rule, message, issue),
            file_path=position.get("Filename") or None,
            line=position.get("Line") or None,
            vuln_id_from_tool=rule,
            # golangci-lint analyses source, so every finding is static.
            static_finding=True,
            dynamic_finding=False,
        )
        finding.unsaved_tags = [f"linter:{linter}"]
        if rule:
            finding.unsaved_tags.append(f"rule:{rule}")
        return finding

    def split_rule(self, text):
        """Split gosec's "G402: message" into the rule id and the message; bidichk has no id."""
        match = RULE_ID.match(text)
        if match:
            return match.group("rule"), match.group("message").strip()
        return None, text

    def severity(self, issue):
        return SEVERITY_MAP.get((issue.get("Severity") or "").strip().lower(), DEFAULT_SEVERITY)

    def describe(self, linter, rule, message, issue):
        lines = [f"**Linter:** {linter}"]
        if rule:
            lines.append(f"**Rule:** {rule}")
        if message:
            lines.append(f"**Message:** {message}")

        source = issue.get("SourceLines") or []
        if source:
            snippet = "\n".join(source)
            lines.append(f"**Source:**\n```go\n{snippet}\n```")
        return "\n".join(lines)
