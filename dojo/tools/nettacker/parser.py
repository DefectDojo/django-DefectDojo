import json
import re

from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

# Nettacker's report carries no severity field, so any severity here is derived from the module that
# produced the event. A scan module reports that something exists - a port answers, a path is served -
# which is an observation, the same call the Naabu and Dirsearch parsers make. A module whose name
# marks it as a vulnerability check is different in kind: it fired against the target.
SCAN_SEVERITY = "Info"
VULNERABILITY_SEVERITY = "Medium"

# Nettacker names its vulnerability modules "<product>_cve_<year>_<number>_vuln", and its other
# modules "<something>_scan" or "<something>_brute". The CVE is only in the module name; the report
# does not repeat it as a field.
VULNERABILITY_MODULE = re.compile(r"_vuln$")
CVE_IN_MODULE = re.compile(r"cve[_-](?P<year>\d{4})[_-](?P<number>\d{4,7})", re.IGNORECASE)


class NettackerParser:

    """Parses the JSON report written by `nettacker -o report.json`."""

    def get_scan_types(self):
        return ["Nettacker Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Nettacker Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import the JSON report written by OWASP Nettacker (`nettacker ... -o report.json`)."

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        # Nettacker writes an EMPTY file when no module produces an event, which is the ordinary
        # result of scanning a target that answers nothing.
        text = content.strip()
        if not text:
            return []

        events = json.loads(text)
        if not isinstance(events, list):
            msg = (
                "Nettacker's report is a JSON array of events; "
                f"got {type(events).__name__}."
            )
            raise TypeError(msg)

        findings = {}
        for event in events:
            if not isinstance(event, dict):
                msg = f"Nettacker's report is a JSON array of events; got a {type(event).__name__} in it."
                raise TypeError(msg)
            module = (event.get("module_name") or "").strip()
            target = (event.get("target") or "").strip()
            port = event.get("port")
            # A module can report the same target and port more than once in a scan, and the scan_id
            # and date differ between runs, so neither belongs in the key.
            key = (target, module, port)
            if key not in findings:
                findings[key] = self.build_finding(event, module, target, port, test)
        return list(findings.values())

    def build_finding(self, event, module, target, port, test):
        is_vulnerability = bool(VULNERABILITY_MODULE.search(module))
        where = f"{target}:{port}" if port is not None else target

        finding = Finding(
            test=test,
            title=f"{module} fired against {where}" if is_vulnerability else f"{module}: {where}",
            severity=VULNERABILITY_SEVERITY if is_vulnerability else SCAN_SEVERITY,
            description=self.build_description(event, module, target, port),
            # The module name is Nettacker's own identity for the check.
            vuln_id_from_tool=module,
            static_finding=False,
            # Nettacker probes a live target rather than reading files.
            dynamic_finding=True,
        )
        if cve := self.cve_from_module(module):
            # The CVE is only in the module name, so this is the one place it can come from.
            finding.unsaved_vulnerability_ids = [cve]
        if target:
            # An event is a host and possibly a port, not a URL, so the endpoint is built from those.
            # A bare host would otherwise be parsed as a URL path, which is why the "//" is needed.
            # An event is a host and possibly a port, not a URL, so those are passed as fields.
            # unsaved_locations and unsaved_endpoints are chosen by V3_FEATURE_LOCATIONS, as in
            # the nmap parser.
            if settings.V3_FEATURE_LOCATIONS:
                finding.unsaved_locations = [LocationData.url(host=target, port=port)]
            else:
                # TODO: Delete this after the move to Locations
                finding.unsaved_endpoints = [Endpoint(host=target, port=port)]
        return finding

    def cve_from_module(self, module):
        if match := CVE_IN_MODULE.search(module):
            return f"CVE-{match.group('year')}-{match.group('number')}"
        return None

    def build_description(self, event, module, target, port):
        parts = [f"**Module:** {module}"]
        if target:
            parts.append(f"**Target:** {target}")
        if port is not None:
            parts.append(f"**Port:** {port}")
        if summary := (event.get("event") or "").strip():
            # Nettacker's own summary of what the module saw.
            parts.append(f"**Event:** {summary}")
        # scan_id and date are deliberately left out: both change on every run, and hashing them into
        # the description would reimport every event on a rescan of an unchanged target.
        return "\n".join(parts)
