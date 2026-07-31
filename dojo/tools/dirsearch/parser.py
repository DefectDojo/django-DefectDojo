import json
from urllib.parse import urlparse

from dojo.models import Endpoint, Finding

# dirsearch reports paths that EXIST, not paths that are wrong. A 200 on /index.html is not a
# weakness; an exposed /.git is - and dirsearch cannot tell them apart. Everything imports at Info and
# triage is by path, matching the ffuf parser and DefectDojo's treatment of an open port from nmap.
DEFAULT_SEVERITY = "Info"


class DirsearchParser:

    """Parses the JSON report produced by `dirsearch --format=json`."""

    def get_scan_types(self):
        return ["Dirsearch Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Dirsearch Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import the JSON report produced by `dirsearch --format=json -o report.json`."

    def get_findings(self, filename, test):
        data = json.load(filename)
        if not isinstance(data, dict):
            msg = f"A dirsearch JSON report is an object; got a {type(data).__name__}."
            raise TypeError(msg)

        info = data.get("info") or {}
        findings = []
        for result in data.get("results") or []:
            if not isinstance(result, dict):
                msg = "Every result in a dirsearch report must be an object."
                raise TypeError(msg)
            findings.append(self.build_finding(result, info, test))
        return findings

    def build_finding(self, result, info, test):
        url = result.get("url") or ""
        status = result.get("status")
        path = urlparse(url).path or "/" if url else "/"

        finding = Finding(
            test=test,
            title=f"HTTP {status}: {path}" if status is not None else f"Discovered: {path}",
            severity=DEFAULT_SEVERITY,
            description=self.build_description(result, info, url, status),
            static_finding=False,
            # dirsearch requests a live service rather than reading files.
            dynamic_finding=True,
        )
        if url:
            finding.unsaved_endpoints = [Endpoint.from_uri(url)]
        return finding

    def build_description(self, result, info, url, status):
        parts = []
        if url:
            parts.append(f"**URL:** {url}")
        if status is not None:
            parts.append(f"**Status:** {status}")
        for key, label in (
            ("content-length", "Content length"),
            ("content-type", "Content type"),
        ):
            if (value := result.get(key)) not in {None, ""}:
                parts.append(f"**{label}:** {value}")
        # dirsearch always emits a redirect key and leaves it null for a direct hit.
        if redirect := result.get("redirect"):
            parts.append(f"**Redirects to:** {redirect}")
        if args := info.get("args"):
            # The wordlist and status filters decide what counted as a hit, so the invocation is
            # part of the evidence.
            parts.append(f"**Command:** `{args}`")
        return "\n".join(parts)
