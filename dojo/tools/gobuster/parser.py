import re

from dojo.location.feature import locations_enabled
from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

# gobuster reports paths that EXIST, not paths that are wrong - the same call the ffuf and Dirsearch
# parsers make. Whether a discovered path matters depends on which path it is.
DEFAULT_SEVERITY = "Info"

# This parser handles gobuster's `dir` mode, which writes one line per hit. There is no JSON output for
# that mode, so the line is the interface:
#   admin                (Status: 301) [Size: 169] [--> http://target/admin/]
#   robots.txt           (Status: 200) [Size: 49]
# The status is REQUIRED, which is what makes a line a dir-mode hit. gobuster's `dns` and `vhost` modes
# write "Found: name" instead - subdomain and virtual-host inventory rather than a weakness, the same
# class as subfinder and dnsx - and those lines are deliberately not imported.
HIT = re.compile(
    r"^\s*(?P<name>\S+)"
    r"\s+\(Status:\s*(?P<status>\d+)\)"
    r"(?:\s+\[Size:\s*(?P<size>\d+)\])?"
    r"(?:\s+\[-->\s*(?P<redirect>[^\]]+)\])?"
    r"\s*$",
)

# Lines gobuster writes that are not hits. Without -q it prints a banner and a progress footer, and a
# user who forgets -q would otherwise import the banner as findings.
NOISE_PREFIXES = (
    "=====",
    "Gobuster",
    "by OJ Reeves",
    "[+]",
    "Progress:",
    "Finished",
    "Starting gobuster",
)


class GobusterParser:

    """Parses the output file written by `gobuster ... -o`."""

    def get_scan_types(self):
        return ["Gobuster Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Gobuster Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import the output file written by `gobuster dir -o report.txt -q` (plain text)."

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        findings = {}
        for raw in content.splitlines():
            line = raw.strip()
            if not line or line.startswith(NOISE_PREFIXES):
                continue
            match = HIT.match(line)
            if not match:
                continue
            name = match.group("name")
            # A wordlist can contain the same entry twice, and gobuster reports each hit, so the
            # name plus status is the key.
            key = (name, match.group("status"))
            if key not in findings:
                findings[key] = self.build_finding(match, name, test)
        return list(findings.values())

    def build_finding(self, match, name, test):
        status = match.group("status")
        redirect = match.group("redirect")

        finding = Finding(
            test=test,
            title=f"HTTP {status}: {self.as_path(name)}",
            severity=DEFAULT_SEVERITY,
            description=self.build_description(match, name, status, redirect),
            static_finding=False,
            # gobuster probes a running service rather than reading files.
            dynamic_finding=True,
        )
        # gobuster's output line holds the path or name but not the host it was scanning, so the only
        # absolute URL available is a redirect target. An endpoint is set when there is one; otherwise
        # the path alone is not enough to build one.
        if redirect and "://" in redirect:
            # Finding.__init__ creates unsaved_locations OR unsaved_endpoints depending on
            # V3_FEATURE_LOCATIONS, and only the matching importer reads it, so the location is
            # built and attached the way the nmap parser does it.
            if locations_enabled():
                finding.unsaved_locations = [LocationData.url(url=redirect.strip())]
            else:
                # TODO: Delete this after the move to Locations
                finding.unsaved_endpoints = [Endpoint.from_uri(redirect.strip())]
        return finding

    def as_path(self, name):
        """Gobuster prints the wordlist entry, without a leading slash, for dir mode."""
        return name if name.startswith("/") else f"/{name}"

    def build_description(self, match, name, status, redirect):
        parts = [f"**Path:** {self.as_path(name)}", f"**Status:** {status}"]
        if size := match.group("size"):
            parts.append(f"**Response size:** {size}")
        if redirect:
            parts.append(f"**Redirects to:** {redirect.strip()}")
        # The host is deliberately not asserted: gobuster's hit lines do not carry it, and inventing
        # one from a redirect would be wrong for any hit that does not redirect.
        parts.append(
            "**Note:** gobuster's output does not record the scanned host, only the path.",
        )
        return "\n".join(parts)
