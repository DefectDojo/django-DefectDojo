import re

from django.conf import settings

from dojo.models import Finding
from dojo.tools.locations import LocationData

# AIDE reports a difference between a baseline and the filesystem. It attaches no severity, and
# whether a change matters depends entirely on which path moved - a new file in /tmp is routine, the
# same change to a system binary is not - so everything imports at one level and the docs page says
# to triage by path.
DEFAULT_SEVERITY = "Medium"

# The three sections AIDE groups its differences under, and the wording each becomes.
SECTIONS = {
    "Added entries": "added",
    "Removed entries": "removed",
    "Changed entries": "changed",
}

# A section banner is a line of dashes wrapping the section name.
SECTION_NAME = re.compile(r"^(?P<name>Added entries|Removed entries|Changed entries|"
                          r"Detailed information about changes|Summary|"
                          r"The attributes of the \(uncompressed\) database\(s\)):?\s*$")

# An entry line is an attribute-change mask, then a colon, then the path:
#   f++++++++++++++++++: /watched/d.txt
#   f > ... ....H      : /watched/a.txt
ENTRY = re.compile(r"^(?P<mask>\S[^:]*?)\s*:\s*(?P<path>/\S.*?)\s*$")

# The detail section repeats each changed path followed by its attribute diffs.
DETAIL_FILE = re.compile(r"^File:\s*(?P<path>/\S.*?)\s*$")
DETAIL_ATTR = re.compile(r"^\s+(?P<attr>\S+)\s*:\s*(?P<values>.+?)\s*$")


class AideParser:

    """Parses the report written by `aide --check`."""

    def get_scan_types(self):
        return ["AIDE Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "AIDE Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import the report produced by `aide --check`."

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")
        lines = content.splitlines()

        entries = self.collect_entries(lines)
        details = self.collect_details(lines)
        return [
            self.build_finding(path, change, mask, details.get(path, []), test)
            for path, change, mask in entries
        ]

    def collect_entries(self, lines):
        """Walk the Added / Removed / Changed sections, which is where the paths live."""
        entries = []
        section = None
        for line in lines:
            if name := SECTION_NAME.match(line.strip()):
                section = SECTIONS.get(name.group("name"))
                continue
            if section is None or not line.strip() or set(line.strip()) == {"-"}:
                continue
            if match := ENTRY.match(line):
                entries.append((match.group("path"), section, match.group("mask").strip()))
        return entries

    def collect_details(self, lines):
        """
        Collect the attribute diffs AIDE prints for each changed path.

        They live in their own section keyed by path rather than beside the entry, so the two halves
        of the report have to be joined up.
        """
        details = {}
        current = None
        in_details = False
        for line in lines:
            stripped = line.strip()
            if name := SECTION_NAME.match(stripped):
                in_details = name.group("name") == "Detailed information about changes"
                current = None
                continue
            if not in_details:
                continue
            if match := DETAIL_FILE.match(stripped):
                current = match.group("path")
                details.setdefault(current, [])
                continue
            if current is None or not stripped or set(stripped) == {"-"}:
                continue
            if match := DETAIL_ATTR.match(line):
                columns = [part.strip() for part in match.group("values").split("|")]
                details[current].append([match.group("attr"), *columns])
            elif details[current]:
                # AIDE wraps a long value - a base64 checksum - onto a continuation line, keeping
                # the old and new values in their own columns. Appending the whole line would splice
                # the tail of the old value onto the head of the new one, so the continuation is
                # joined column by column.
                continuation = [part.strip() for part in stripped.split("|")]
                entry = details[current][-1]
                for index, part in enumerate(continuation, start=1):
                    if index < len(entry):
                        entry[index] += part
                    else:
                        entry.append(part)
        return {
            path: [f"{row[0]}: {' | '.join(row[1:])}" for row in rows]
            for path, rows in details.items()
        }

    def build_finding(self, path, change, mask, details, test):
        finding = Finding(
            test=test,
            title=f"File {change}: {path}",
            severity=DEFAULT_SEVERITY,
            description=self.build_description(path, change, mask, details),
            file_path=path,
            static_finding=False,
            # AIDE compares a baseline against a live filesystem rather than reading source.
            dynamic_finding=True,
        )
        if settings.V3_FEATURE_LOCATIONS:
            # A path but never a line: AIDE tracks whole files.
            finding.unsaved_locations.append(LocationData.code(file_path=path))
        return finding

    def build_description(self, path, change, mask, details):
        parts = [f"**Change:** {change}", f"**Path:** {path}"]
        if mask:
            # The mask is AIDE's own shorthand for which attributes moved; keeping it lets a reader
            # cross-reference the report.
            parts.append(f"**Attribute mask:** `{mask}`")
        if details:
            parts.append("**Attributes that changed:**")
            parts.extend(f"- {detail}" for detail in details)
        return "\n".join(parts)
