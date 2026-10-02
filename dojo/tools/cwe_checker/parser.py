import json
import re

from dojo.models import Finding

# cwe_checker does not grade its findings - there is no severity, score or confidence anywhere in
# its output - so every finding is imported at one level and the docs page says to triage by CWE.
# Medium is used rather than something louder because the check set mixes genuine memory-safety
# defects (double free, use after free) with advisory ones (the binary retains debug symbols).
DEFAULT_SEVERITY = "Medium"

# Check names are of the form "CWE676".
CWE_NAME_PATTERN = re.compile(r"^CWE(\d+)$")

# Descriptions lead with the check's human-readable name in parentheses, e.g.
# "(Double Free) Object may have been freed before at 4198851".
DESCRIPTION_PATTERN = re.compile(r"^\((?P<title>[^)]+)\)\s*(?P<detail>.*)$", re.DOTALL)


class CweCheckerParser:

    """Parses the JSON report produced by `cwe_checker --json`."""

    def get_scan_types(self):
        return ["cwe_checker Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "cwe_checker Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import the JSON report produced by `cwe_checker --json --quiet --out report.json <binary>`."

    def get_findings(self, filename, test):
        data = json.load(filename)
        if not isinstance(data, list):
            msg = f"cwe_checker reports are a JSON array of warnings; got a {type(data).__name__}."
            raise TypeError(msg)

        findings = []
        for warning in data:
            if not isinstance(warning, dict):
                msg = "Every warning in a cwe_checker report must be an object."
                raise TypeError(msg)
            findings.append(self.build_finding(warning, test))
        return findings

    def build_finding(self, warning, test):
        name = warning.get("name") or ""
        title, detail = self.split_description(warning.get("description") or "")

        return Finding(
            test=test,
            title=title or name or "cwe_checker warning",
            cwe=self.extract_cwe(name),
            severity=DEFAULT_SEVERITY,
            description=self.build_body(name, detail, warning),
            # cwe_checker analyses a compiled binary, so there is no source file or line to report;
            # a finding is located by symbol and virtual address instead, both kept in the body.
            static_finding=True,
            dynamic_finding=False,
            vuln_id_from_tool=name or None,
        )

    def split_description(self, description):
        match = DESCRIPTION_PATTERN.match(description)
        if match:
            return match.group("title").strip(), match.group("detail").strip()
        return "", description.strip()

    def extract_cwe(self, name):
        match = CWE_NAME_PATTERN.match(name or "")
        return int(match.group(1)) if match else None

    def build_body(self, name, detail, warning):
        parts = []
        if detail:
            parts.append(detail)
        if name:
            parts.append(f"**Check:** {name}")
        if version := warning.get("version"):
            parts.append(f"**Check version:** {version}")
        if symbols := [symbol for symbol in warning.get("symbols") or [] if symbol]:
            parts.append(f"**Symbols:** {', '.join(symbols)}")
        if addresses := self.format_addresses(warning.get("addresses")):
            parts.append(f"**Addresses:** {addresses}")
        if tids := [tid for tid in warning.get("tids") or [] if tid]:
            parts.append(f"**Term identifiers:** {', '.join(tids)}")
        for extra in warning.get("other") or []:
            # "other" holds a list of string lists, but a check is free to put a bare string there.
            text = (
                " ".join(str(value) for value in extra if value)
                if isinstance(extra, list)
                else str(extra)
            )
            if text:
                parts.append(f"**Details:** {text}")
        return "\n".join(parts)

    def format_addresses(self, addresses):
        """
        cwe_checker reports virtual addresses as decimal strings.

        Both forms are shown, because the decimal is what the report contains while the hexadecimal
        is what a disassembler displays.
        """
        rendered = []
        for address in addresses or []:
            try:
                rendered.append(f"{hex(int(address))} ({address})")
            except (TypeError, ValueError):
                rendered.append(str(address))
        return ", ".join(rendered)
