import re

from dojo.models import Finding

# firmwalker reports where to look in an extracted firmware image: a file whose name matches a
# pattern, or a file whose contents mention one. Whether a hit matters depends on the firmware - a
# private key file is a problem in a shipped image and expected in a development one - so every hit
# is an observation, the same call the ffuf, Dirsearch and Naabu parsers make.
DEFAULT_SEVERITY = "Info"

# A section header, e.g. "***Search for password files***".
SECTION = re.compile(r"^\*{3}(?P<title>.+?)\*{3}\s*$")
# firmwalker writes subsection headers two ways: "##################################### passwd" for
# file searches and "-------------------- admin --------------------" for content searches.
HASH_SUBSECTION = re.compile(r"^#{5,}\s*(?P<name>.*?)\s*$")
DASH_SUBSECTION = re.compile(r"^-{5,}\s*(?P<name>.*?)\s*-{5,}\s*$")

# The section naming the directory that was scanned; it holds the path, not a hit.
FIRMWARE_DIRECTORY = "firmware directory"
# firmwalker also drops a plain `ls -la` of etc/ssl into the report. Those lines look like hits but
# are a directory listing, complete with a modification time that changes between runs.
LISTING_PREFIX = "list "


class FirmwalkerParser:

    """Parses the report written by firmwalker."""

    def get_scan_types(self):
        return ["Firmwalker Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Firmwalker Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import the report written by `firmwalker.sh <firmware-dir> <report>`."

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        findings = {}
        section = None
        subsection = None
        for raw in content.splitlines():
            line = raw.rstrip()
            if not line.strip():
                continue

            if header := SECTION.match(line):
                section = header.group("title").strip()
                # "Search for" prefixes every real section and says nothing a title needs.
                section = re.sub(r"^Search for\s+", "", section).strip()
                subsection = None
                continue
            if header := DASH_SUBSECTION.match(line):
                subsection = header.group("name")
                continue
            if header := HASH_SUBSECTION.match(line):
                subsection = header.group("name")
                continue

            if section is None or self.is_skipped(section):
                continue

            path, matched = self.split_hit(line.strip())
            # firmwalker searches overlapping patterns - "authorized_keys" and "*authorized_keys*",
            # or several content patterns - so one file is reported several times within a section.
            # That is one finding, listing every pattern that matched it.
            key = (section, path, matched)
            if key not in findings:
                findings[key] = {
                    "section": section,
                    "path": path,
                    "matched": matched,
                    "patterns": [],
                }
            if subsection and subsection not in findings[key]["patterns"]:
                findings[key]["patterns"].append(subsection)

        return [self.build_finding(entry, test) for entry in findings.values()]

    def is_skipped(self, section):
        lowered = section.lower()
        return lowered == FIRMWARE_DIRECTORY or lowered.startswith(LISTING_PREFIX)

    def split_hit(self, hit):
        """
        Split a grep-style hit into its path and the text that matched.

        Only a hit that starts with "/" is split, and only on its first colon: a URL contains a colon
        too, and splitting one would leave "https" as the path.
        """
        if hit.startswith("/") and ":" in hit:
            path, _, matched = hit.partition(":")
            return path, matched.strip()
        return hit, None

    def build_finding(self, entry, test):
        path = entry["path"]
        return Finding(
            test=test,
            title=f"{path} ({entry['section']})",
            severity=DEFAULT_SEVERITY,
            description=self.build_description(entry),
            # A hit is only a file path when it looks like one; an address, URL or email is not.
            file_path=path if path.startswith("/") else None,
            # firmwalker reads an extracted image rather than probing a running device.
            static_finding=True,
            dynamic_finding=False,
        )

    def build_description(self, entry):
        parts = [f"**Found by:** firmwalker, searching for {entry['section']}"]
        if entry["path"].startswith("/"):
            parts.append(f"**Path:** {entry['path']}")
        else:
            parts.append(f"**Value:** {entry['path']}")
        if entry["matched"]:
            parts.append(f"**Matched:** {entry['matched']}")
        if entry["patterns"]:
            parts.append(f"**Patterns that matched:** {', '.join(entry['patterns'])}")
        return "\n".join(parts)
