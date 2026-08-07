import json

from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

# An open port is an observation, not a weakness - whether it should be open is a question about the
# host, which masscan cannot answer. DefectDojo already treats nmap's open ports as Info, and this
# follows that precedent.
DEFAULT_SEVERITY = "Info"


class MasscanParser:

    """Parses the JSON output of `masscan -oJ`."""

    def get_scan_types(self):
        return ["Masscan Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Masscan Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import the JSON output of `masscan -oJ` (open ports, reported as Info)."

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        records = self.load(content)

        findings = {}
        for record in records:
            if not isinstance(record, dict):
                msg = (
                    "Masscan output is a JSON array of host objects; "
                    f"got a {type(record).__name__} in the array."
                )
                raise TypeError(msg)
            host = record.get("ip") or ""
            for port_record in record.get("ports") or []:
                if not isinstance(port_record, dict):
                    continue
                # masscan reports a closed port when it gets a RST, which is the opposite of a
                # finding, so only open ports are imported.
                if (port_record.get("status") or "open").lower() != "open":
                    continue
                protocol = (port_record.get("proto") or "tcp").lower()
                # A retransmitted probe can be answered twice, so the same open port can appear in
                # more than one record. Keying on host, port and protocol collapses those.
                key = (host, port_record.get("port"), protocol)
                if key not in findings:
                    findings[key] = self.build_finding(record, port_record, host, protocol, test)
        return list(findings.values())

    def load(self, content):
        """
        Masscan writes an EMPTY file when it finds nothing, rather than an empty array.

        That is the ordinary result of scanning a host with the ports in question closed, so it has
        to parse rather than raise. Some masscan versions also leave a trailing comma before the
        closing bracket, which is not valid JSON; the file is otherwise fine, so the comma is
        tolerated instead of failing an import over it.
        """
        text = content.strip()
        if not text:
            return []
        try:
            records = json.loads(text)
        except ValueError:
            repaired = text
            if repaired.endswith("]"):
                repaired = repaired[:-1].rstrip().rstrip(",") + "]"
            try:
                records = json.loads(repaired)
            except ValueError as error:
                msg = f"Masscan output could not be parsed as JSON: {error}"
                raise ValueError(msg) from error
        if not isinstance(records, list):
            msg = (
                "Masscan output is a JSON array of host objects, one per open port; "
                f"got {type(records).__name__}."
            )
            raise TypeError(msg)
        return records

    def build_finding(self, record, port_record, host, protocol, test):
        port = port_record.get("port")

        finding = Finding(
            test=test,
            title=f"Open port: {port}/{protocol} on {host}" if host else f"Open port: {port}/{protocol}",
            severity=DEFAULT_SEVERITY,
            description=self.build_description(record, port_record, host, port, protocol),
            static_finding=False,
            # masscan sends packets to a live host rather than reading files.
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

    def build_description(self, record, port_record, host, port, protocol):
        parts = []
        if host:
            parts.append(f"**Host:** {host}")
        if port is not None:
            parts.append(f"**Port:** {port}/{protocol}")
        if reason := port_record.get("reason"):
            # masscan records why it called the port open, which is "syn-ack" for a normal SYN scan.
            parts.append(f"**Reason:** {reason}")
        if (ttl := port_record.get("ttl")) is not None:
            parts.append(f"**TTL:** {ttl}")
        if timestamp := record.get("timestamp"):
            parts.append(f"**Timestamp:** {timestamp}")
        return "\n".join(parts)
