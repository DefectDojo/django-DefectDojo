import re

from dojo.models import Finding


class DebsecanParser:

    """
    Parser for debsecan, the Debian security analyzer.

    debsecan compares the packages installed on a Debian system against the Debian security
    tracker and lists the CVEs that apply. It has no machine readable output format, so this
    parses the two text formats that carry the information:

    - ``--format detail`` is the one to prefer. Each CVE is a block holding a truncated
      description, the installed package and version, and where a fix has landed.
    - ``--format simple`` (and ``summary``) is one ``CVE-ID package`` pair per line, with no
      further detail.

    The format is detected from the file, so either can be imported. One Finding is created per
    CVE and package pair, since a CVE affecting three packages is three packages to upgrade.
    """

    CVE_ONLY = re.compile(r"^(?P<cve>(?:CVE|TEMP)-[\w.-]+)\s*$")
    CVE_AND_PACKAGE = re.compile(r"^(?P<cve>(?:CVE|TEMP)-[\w.-]+)\s+(?P<package>\S+)\s*(?P<flags>.*)$")
    INSTALLED = re.compile(r"^\s+installed:\s+(?P<package>\S+)(?:\s+(?P<version>\S+))?\s*$")
    BUILT_FROM = re.compile(r"^\s+\(built from (?P<source>.+)\)\s*$")
    FIXED = re.compile(r"^\s+fixed (?P<where>in \S+|on branch):\s*(?P<detail>.+?)\s*$")

    def get_scan_types(self):
        return ["debsecan Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import debsecan output. Generate a report with 'debsecan --format detail', which "
            "carries the package and fix detail. The 'simple' format is also accepted."
        )

    def get_findings(self, file, test):
        content = file.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")

        entries = self._parse_detail(content)
        if entries is None:
            entries = self._parse_simple(content)
        return [self._to_finding(entry, test) for entry in entries]

    def _parse_detail(self, content):
        """
        Parse the block-per-CVE detail format, or return None if this is not that format.

        A detail block starts with a CVE id alone on a line; the simple format always has the
        package name on the same line, so the first CVE line tells the two apart.
        """
        lines = content.splitlines()
        if not any(self.CVE_ONLY.match(line) for line in lines):
            return None

        entries = []
        current = None
        for line in lines:
            cve_match = self.CVE_ONLY.match(line)
            if cve_match:
                if current:
                    entries.append(current)
                current = {"cve": cve_match.group("cve"), "description": [], "fixes": []}
                continue
            if current is None:
                continue

            installed = self.INSTALLED.match(line)
            if installed:
                current["package"] = installed.group("package")
                current["version"] = installed.group("version")
                continue
            built_from = self.BUILT_FROM.match(line)
            if built_from:
                current["source"] = built_from.group("source").strip()
                continue
            fixed = self.FIXED.match(line)
            if fixed:
                current["fixes"].append(f"fixed {fixed.group('where')}: {fixed.group('detail')}")
                continue
            if line.strip():
                current["description"].append(line.strip())

        if current:
            entries.append(current)
        return entries

    def _parse_simple(self, content):
        entries = []
        for line in content.splitlines():
            match = self.CVE_AND_PACKAGE.match(line)
            if not match:
                continue
            entries.append({
                "cve": match.group("cve"),
                "package": match.group("package"),
                "description": [],
                "fixes": [],
                "flags": match.group("flags").strip(),
            })
        return entries

    def _to_finding(self, entry, test):
        cve = entry["cve"]
        package = entry.get("package")
        fixes = entry.get("fixes") or []

        description = []
        if entry.get("description"):
            description.append(" ".join(entry["description"]))
        description.append(f"**CVE:** {cve}")
        if package:
            description.append(f"**Installed package:** {package}")
        if entry.get("version"):
            description.append(f"**Installed version:** {entry['version']}")
        if entry.get("source"):
            description.append(f"**Built from:** {entry['source']}")
        if entry.get("flags"):
            description.append(f"**Flags:** {entry['flags']}")
        if fixes:
            description.append("**Fix availability:**\n" + "\n".join(f"- {fix}" for fix in fixes))
        else:
            description.append("**Fix availability:** debsecan reported no fixed version")

        finding = Finding(
            title=f"{cve}: {package}" if package else cve,
            test=test,
            description="\n".join(description),
            # debsecan reports applicability, not severity. See the docs page for the reasoning.
            severity="Medium",
            component_name=package or None,
            component_version=entry.get("version") or None,
            mitigation="\n".join(fixes) or None,
            vuln_id_from_tool=cve,
            static_finding=True,
            dynamic_finding=False,
        )
        # Only real CVE ids are vulnerability ids; debsecan's TEMP- placeholders are its own
        # identifiers for issues the tracker has not assigned a CVE to yet.
        if cve.startswith("CVE-"):
            finding.unsaved_vulnerability_ids = [cve]
        return finding
