import json
from urllib.parse import urlparse

from dojo.location.feature import locations_enabled
from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

# ffuf reports what it FOUND, not what is wrong. A 200 on /index.html is not a weakness; an exposed
# /.git or /backup is. The tool cannot tell them apart, so everything imports at Info and triage is by
# path - the same treatment DefectDojo's nmap parser gives an open port.
DEFAULT_SEVERITY = "Info"

# ffuf substitutes the wordlist entry for this keyword by default.
DEFAULT_KEYWORD = "FUZZ"

# ffuf adds its own per-request hash to the input map; it identifies a request, not a finding.
INTERNAL_INPUTS = {"FFUFHASH"}


class FfufParser:

    """Parses the JSON report produced by `ffuf -of json`."""

    def get_scan_types(self):
        return ["ffuf Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "ffuf Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import the JSON report produced by `ffuf -of json -o report.json`."

    def get_findings(self, filename, test):
        data = json.load(filename)
        if not isinstance(data, dict):
            msg = f"An ffuf JSON report is an object; got a {type(data).__name__}."
            raise TypeError(msg)

        commandline = data.get("commandline")
        findings = []
        for result in data.get("results") or []:
            if not isinstance(result, dict):
                msg = "Every result in an ffuf report must be an object."
                raise TypeError(msg)
            findings.append(self.build_finding(result, commandline, test))
        return findings

    def build_finding(self, result, commandline, test):
        url = result.get("url") or ""
        status = result.get("status")
        path = self.path_of(url)

        finding = Finding(
            test=test,
            title=f"HTTP {status}: {path}" if status is not None else f"Discovered: {path}",
            severity=DEFAULT_SEVERITY,
            description=self.build_description(result, commandline, url, status),
            static_finding=False,
            # ffuf probes a running service rather than reading files.
            dynamic_finding=True,
        )
        if url:
            # A full URL, so from_uri parses it directly - no "//" prefix needed as it is for tools
            # that report a bare hostname.
            # Finding.__init__ creates unsaved_locations OR unsaved_endpoints depending on
            # V3_FEATURE_LOCATIONS, and only the matching importer reads it, so the location is
            # built and attached the way the nmap parser does it.
            if locations_enabled():
                finding.unsaved_locations = [LocationData.url(url=url)]
            else:
                # TODO: Delete this after the move to Locations
                finding.unsaved_endpoints = [Endpoint.from_uri(url)]
        return finding

    def path_of(self, url):
        """The path is what identifies a hit; the host is carried by the endpoint."""
        if not url:
            return "/"
        parsed = urlparse(url)
        return parsed.path or "/"

    def build_description(self, result, commandline, url, status):
        parts = []
        if url:
            parts.append(f"**URL:** {url}")
        if status is not None:
            parts.append(f"**Status:** {status}")

        # The wordlist entry that produced the hit, which is not always visible in the path.
        inputs = {
            key: value
            for key, value in (result.get("input") or {}).items()
            if key not in INTERNAL_INPUTS
        }
        for key, value in sorted(inputs.items()):
            label = "Payload" if key == DEFAULT_KEYWORD else f"Payload ({key})"
            parts.append(f"**{label}:** {value}")

        for key, label in (
            ("length", "Response length"),
            ("words", "Response words"),
            ("lines", "Response lines"),
            ("content-type", "Content type"),
        ):
            if (value := result.get(key)) not in {None, ""}:
                parts.append(f"**{label}:** {value}")
        if redirect := result.get("redirectlocation"):
            parts.append(f"**Redirects to:** {redirect}")
        if commandline:
            # The matcher and filter settings decide what counted as a hit, so the command that
            # produced the report is part of the evidence.
            parts.append(f"**Command:** `{commandline}`")
        return "\n".join(parts)
