import re

from dojo.models import Finding

# A YARA rule fires because someone wrote it to fire, but what the match MEANS is entirely up to the
# rule. A ruleset that records a severity in its metadata is believed; anything else gets Medium.
DEFAULT_SEVERITY = "Medium"
SEVERITIES = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "moderate": "Medium",
    "low": "Low",
    "info": "Info",
    "informational": "Info",
}

# A match line is "RuleName /path/to/file", or with -m "RuleName [metadata] /path/to/file". The path
# may contain spaces, so the metadata is matched first and the rest of the line is the path.
MATCH = re.compile(
    r"^(?P<rule>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s+\[(?P<meta>.*)\])?"
    r"\s+(?P<path>\S.*?)\s*$",
)

# With -s, each match is followed by its offsets: "0x1f:$bash: bash -i >& /dev/tcp/". The matched text
# is file content and may contain anything, including colons, so only the first two are separators.
STRING_MATCH = re.compile(r"^(?P<offset>0x[0-9a-fA-F]+):(?P<identifier>\$[A-Za-z0-9_]*):\s?(?P<text>.*)$")

# yara prints metadata as one bracketed list, and a value may contain a comma or an escaped quote, so
# splitting on commas is wrong. Integer values are printed as "key =90" - with a space before the "="
# but not after - while string and boolean values get no space at all, hence \s* on both sides.
METADATA = re.compile(
    r'(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*'
    r'(?:"(?P<text>(?:[^"\\]|\\.)*)"|(?P<other>[^,\]]*))',
)


class YaraParser:

    """Parses the text output of the YARA scanner."""

    def get_scan_types(self):
        return ["YARA Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "YARA Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import the output of `yara`. Run it with -m to carry rule metadata (including "
            "severity) and -s to carry the matched offsets."
        )

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        findings = {}
        current = None
        for raw in content.splitlines():
            line = raw.rstrip()
            if not line.strip():
                continue

            # An offset line belongs to the match above it, so it is tested first: a matched string
            # can otherwise look like the start of a new match.
            if current is not None and (strings := STRING_MATCH.match(line)):
                current["strings"].append(strings.groupdict())
                continue

            match = MATCH.match(line)
            if not match:
                # yara writes warnings and errors to stderr, so anything unrecognised here is not
                # part of the results and is skipped rather than guessed at.
                continue
            rule = match.group("rule")
            path = match.group("path")
            metadata = self.parse_metadata(match.group("meta"))
            # A rule can match the same file more than once; that is one finding, with every matched
            # offset listed in the description.
            key = (rule, path)
            if key not in findings:
                findings[key] = {"rule": rule, "path": path, "meta": metadata, "strings": []}
            current = findings[key]

        return [self.build_finding(entry, test) for entry in findings.values()]

    def parse_metadata(self, raw):
        """Turn yara's bracketed metadata list into a dict, keeping the declared order."""
        metadata = {}
        if not raw:
            return metadata
        for match in METADATA.finditer(raw):
            value = match.group("text")
            if value is None:
                value = (match.group("other") or "").strip()
            else:
                # yara escapes quotes and backslashes when printing a string value.
                value = value.replace('\\"', '"').replace("\\\\", "\\")
            if value:
                metadata[match.group("key")] = value
        return metadata

    def build_finding(self, entry, test):
        metadata = entry["meta"]
        severity = SEVERITIES.get((metadata.get("severity") or "").lower(), DEFAULT_SEVERITY)

        return Finding(
            test=test,
            title=f"{entry['rule']} matched {entry['path']}",
            severity=severity,
            description=self.build_description(entry, metadata),
            file_path=entry["path"],
            # The rule name is the tool's own identity for the detection.
            vuln_id_from_tool=entry["rule"],
            # yara reads files rather than probing a running service.
            static_finding=True,
            dynamic_finding=False,
        )

    def build_description(self, entry, metadata):
        parts = [f"**Rule:** {entry['rule']}", f"**File:** {entry['path']}"]
        if description := metadata.get("description"):
            parts.append(f"**Rule description:** {description}")
        # Everything else the ruleset recorded is kept, because which keys a ruleset uses is its own
        # choice - author, reference, date, confidence and so on all show up in practice.
        for key, value in metadata.items():
            if key not in {"description", "severity"}:
                parts.append(f"**{key}:** {value}")
        if entry["strings"]:
            parts.extend(("", "**Matched:**"))
            parts.extend(
                f"- `{item['offset']}` {item['identifier']}: {item['text']}"
                for item in entry["strings"]
            )
        return "\n".join(parts)
