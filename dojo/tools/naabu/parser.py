import json

from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

# An open port is an observation, not a weakness - whether it should be open is a question about the
# host, which naabu cannot answer. DefectDojo already treats nmap's open ports as Info, and this
# follows that precedent.
DEFAULT_SEVERITY = "Info"


class NaabuParser:

    """Parses the JSON Lines output of `naabu -json`."""

    def get_scan_types(self):
        return ["Naabu Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Naabu Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import the JSON Lines output of `naabu -json` (one object per line, not a JSON array)."

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        findings = {}
        for raw in content.splitlines():
            line = raw.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError as error:
                msg = f"Naabu output is JSON Lines; a line could not be parsed: {error}"
                raise ValueError(msg) from error
            if not isinstance(record, dict):
                # A whole JSON array on one line lands here rather than in the decode error above,
                # and confusing the two formats is the likeliest mistake, so say which is expected.
                msg = (
                    "Naabu output is JSON Lines - one object per line, not a JSON array; "
                    f"got a {type(record).__name__} on a line."
                )
                raise TypeError(msg)

            # naabu reports the same open port once per scan pass, so a single run can list a port
            # several times with different timestamps. Keying on host, port and protocol collapses
            # those; without it every open port imports twice.
            key = (
                record.get("ip") or record.get("host") or "",
                record.get("port"),
                (record.get("protocol") or "tcp").lower(),
            )
            if key not in findings:
                findings[key] = self.build_finding(record, test)
        return list(findings.values())

    def build_finding(self, record, test):
        host = record.get("host") or record.get("ip") or ""
        address = record.get("ip") or ""
        port = record.get("port")
        protocol = (record.get("protocol") or "tcp").lower()

        finding = Finding(
            test=test,
            title=f"Open port: {port}/{protocol} on {host}" if host else f"Open port: {port}/{protocol}",
            severity=DEFAULT_SEVERITY,
            description=self.build_description(record, host, address, port, protocol),
            static_finding=False,
            # naabu connects to a live host rather than reading files.
            dynamic_finding=True,
        )
        if host and port:
            # An open port is a host and port, not a URL, so the endpoint is built from those two.
            # A bare host would otherwise be parsed as a URL path, which is why the "//" is needed.
            # An open port is a host and a port, not a URL, so those are passed as fields rather
            # than parsed out of a string. unsaved_locations and unsaved_endpoints are chosen by
            # V3_FEATURE_LOCATIONS, as in the nmap parser.
            if settings.V3_FEATURE_LOCATIONS:
                finding.unsaved_locations = [LocationData.url(host=host, port=port)]
            else:
                # TODO: Delete this after the move to Locations
                finding.unsaved_endpoints = [Endpoint(host=host, port=port)]
        return finding

    def build_description(self, record, host, address, port, protocol):
        parts = []
        if host:
            parts.append(f"**Host:** {host}")
        if address and address != host:
            # naabu resolves a hostname target and reports both.
            parts.append(f"**Address:** {address}")
        if port is not None:
            parts.append(f"**Port:** {port}/{protocol}")
        if (tls := record.get("tls")) is not None:
            # naabu probes whether the port speaks TLS, which is worth keeping.
            parts.append(f"**TLS:** {'yes' if tls else 'no'}")
        if timestamp := record.get("timestamp"):
            parts.append(f"**First seen:** {timestamp}")
        return "\n".join(parts)
