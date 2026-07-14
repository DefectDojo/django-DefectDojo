import csv
import io

from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

SEVERITY_MAPPING = {
    "Info": "Info",
    "Low": "Low",
    "Medium": "Medium",
    "High": "High",
    "Critical": "Critical",
}


class AlertlogicParser:

    def get_scan_types(self):
        return ["Alert Logic Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Alert Logic vulnerability scan findings (CSV)."

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8-sig")
        elif content.startswith("﻿"):
            content = content.lstrip("﻿")

        reader = csv.DictReader(io.StringIO(content), delimiter=",", quotechar='"')
        findings = []
        for row in reader:
            vuln = (row.get("Vulnerability") or "").strip()
            if not vuln:
                continue

            severity_raw = (row.get("Severity") or "").strip()
            severity = SEVERITY_MAPPING.get(severity_raw, "Info")

            title = vuln[:497] + "..." if len(vuln) > 500 else vuln

            description = _build_description(row)
            mitigation = (row.get("Resolution") or "").strip()
            component_name = (row.get("Asset Name") or "").strip() or None
            unique_id = (row.get("Vulnerability ID") or "").strip() or None
            cve = (row.get("CVE") or "").strip()

            finding = Finding(
                test=test,
                title=title,
                severity=severity,
                description=description,
                mitigation=mitigation,
                component_name=component_name,
                unique_id_from_tool=unique_id,
                static_finding=True,
                dynamic_finding=False,
            )

            cvssv3_score = _parse_cvss(row.get("CVSS Score"))
            if cvssv3_score is not None:
                finding.cvssv3_score = cvssv3_score

            if cve:
                finding.unsaved_vulnerability_ids = [cve]

            _add_locations(
                finding,
                row.get("IP Address"),
                row.get("Protocol/Port"),
            )

            tags = _build_tags(row)
            if tags:
                finding.unsaved_tags = tags

            findings.append(finding)

        return findings


def _build_description(row):
    field_order = [
        ("Description", "Description"),
        ("Evidence", "Evidence"),
        ("Operating System", "Operating System"),
        ("Vulnerability ID", "Vulnerability ID"),
        ("Vulnerability Span ID", "Vulnerability Span ID"),
        ("Vulnerability Key", "Vulnerability Key"),
        ("Asset Key", "Asset Key"),
        ("Asset Type", "Asset Type"),
        ("Service", "Service"),
        ("Category", "Category"),
        ("VPC/Network", "VPC/Network"),
        ("Deployment Name", "Deployment Name"),
        ("Customer Account", "Customer Account"),
        ("First Seen", "First Seen"),
        ("Last Scanned", "Last Scanned"),
        ("Published Date", "Published Date"),
        ("Age (days)", "Age (days)"),
        ("CISA Known Exploited", "CISA Known Exploited"),
    ]
    parts = []
    for source_field, label in field_order:
        value = (row.get(source_field) or "").strip()
        if value:
            parts.append(f"**{label}:** {value}")
    return "\n\n".join(parts)


def _parse_cvss(value):
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _add_locations(finding, ip_field, protoport_field):
    if not ip_field:
        return
    protocol, port = _parse_proto_port(protoport_field)
    for raw_host in ip_field.split(","):
        host = raw_host.strip()
        if not host:
            continue
        if settings.V3_FEATURE_LOCATIONS:
            finding.unsaved_locations.append(
                LocationData.url(host=host, protocol=protocol or "", port=port),
            )
        else:
            # TODO: Delete this after the move to Locations
            kwargs = {"host": host}
            if protocol:
                kwargs["protocol"] = protocol
            if port:
                kwargs["port"] = port
            finding.unsaved_endpoints.append(Endpoint(**kwargs))


def _parse_proto_port(value):
    if not value:
        return None, None
    value = value.strip()
    if "/" not in value:
        return None, None
    proto, _, port_str = value.partition("/")
    proto = proto.strip().lower() or None
    try:
        port = int(port_str.strip())
    except (ValueError, TypeError):
        port = None
    if port == 0:
        port = None
    return proto, port


def _build_tags(row):
    tags = []
    if (row.get("CISA Known Exploited") or "").strip().lower() == "yes":
        tags.append("cisa-known-exploited")
    return tags
