import json
import re

from django.conf import settings

from dojo.models import Finding
from dojo.tools.locations import LocationData

# njsscan groups its output into the source it scanned: JavaScript/Node files, and the template
# files rendered by a framework. Both hold the same rule-keyed structure.
SECTIONS = ("nodejs", "templates")

# njsscan reuses Semgrep's severity vocabulary, so the mapping matches the Semgrep parser's.
SEVERITIES = {
    "CRITICAL": "Critical",
    "ERROR": "High",
    "HIGH": "High",
    "WARNING": "Medium",
    "MEDIUM": "Medium",
    "INFO": "Low",
    "LOW": "Low",
}

CWE_PATTERN = re.compile(r"CWE-(\d+)")


class NjsscanParser:

    """Parses the JSON report produced by `njsscan --json`."""

    def get_scan_types(self):
        return ["njsscan Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "njsscan Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import the JSON report produced by `njsscan --json -o report.json <path>`."

    def get_findings(self, filename, test):
        data = json.load(filename)
        if not isinstance(data, dict):
            msg = f"njsscan reports are a JSON object; got a {type(data).__name__}."
            raise TypeError(msg)

        dupes = {}
        for section in SECTIONS:
            for rule_id, rule in (data.get(section) or {}).items():
                metadata = rule.get("metadata") or {}
                for match in rule.get("files") or []:
                    self.add_finding(rule_id, section, metadata, match, test, dupes)
        return list(dupes.values())

    def add_finding(self, rule_id, section, metadata, match, test, dupes):
        file_path = match.get("file_path")
        # match_lines is a [start, end] pair; a multi-line match reports the range.
        lines = match.get("match_lines") or []
        line = lines[0] if lines else None

        finding = Finding(
            test=test,
            title=rule_id,
            severity=self.convert_severity(metadata.get("severity")),
            description=self.build_description(section, metadata, match),
            cwe=self.extract_cwe(metadata.get("cwe")),
            file_path=file_path,
            line=line,
            static_finding=True,
            dynamic_finding=False,
            vuln_id_from_tool=rule_id,
            nb_occurences=1,
        )
        if settings.V3_FEATURE_LOCATIONS and file_path:
            finding.unsaved_locations.append(
                LocationData.code(file_path=file_path, line=line),
            )

        # One rule can match the same file more than once, so the line has to be part of the key.
        dupe_key = f"{section}|{rule_id}|{file_path}|{line}"
        if dupe_key in dupes:
            dupes[dupe_key].nb_occurences += 1
        else:
            dupes[dupe_key] = finding

    def convert_severity(self, value):
        if not value:
            return "Info"
        severity = SEVERITIES.get(value.upper())
        if severity is None:
            msg = f"Unknown value for severity: {value}"
            raise ValueError(msg)
        return severity

    def extract_cwe(self, value):
        """The CWE arrives as a full description, e.g. "CWE-327: Use of a Broken ...", not a number."""
        if not value:
            return None
        match = CWE_PATTERN.search(value)
        return int(match.group(1)) if match else None

    def build_description(self, section, metadata, match):
        parts = []
        if description := metadata.get("description"):
            parts.append(f"**Result message:** {description}")
        if owasp := metadata.get("owasp-web"):
            parts.append(f"**OWASP:** {owasp}")
        if cwe := metadata.get("cwe"):
            parts.append(f"**CWE:** {cwe}")
        if reference := metadata.get("reference"):
            parts.append(f"**Reference:** {reference}")
        parts.append(f"**Scanned as:** {section}")

        lines = match.get("match_lines") or []
        if len(lines) == 2 and lines[0] != lines[1]:
            parts.append(f"**Lines:** {lines[0]}-{lines[1]}")
        position = match.get("match_position") or []
        if len(position) == 2:
            parts.append(f"**Columns:** {position[0]}-{position[1]}")

        if snippet := match.get("match_string"):
            # Same guard the Semgrep parser applies: a snippet containing "<![" breaks rendering,
            # see https://github.com/DefectDojo/django-DefectDojo/issues/8435.
            if "<![" in snippet:
                snippet = snippet.replace("<![", "<! [")
                parts.append(
                    "**Snippet:** ***Caution:*** Please remove the space between `!` and `[` to "
                    "have the real value due to a workaround to circumvent "
                    "[#8435](https://github.com/DefectDojo/django-DefectDojo/issues/8435).\n"
                    f"```\n{snippet}\n```",
                )
            else:
                parts.append(f"**Snippet:**\n```\n{snippet}\n```")
        return "\n".join(parts)
