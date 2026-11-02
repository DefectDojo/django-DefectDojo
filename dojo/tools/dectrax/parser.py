import json
from contextlib import suppress
from datetime import UTC, datetime
from ipaddress import ip_address

from dojo.location.feature import locations_enabled
from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

SEVERITY_MAPPING = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Info",
    "INFORMATIONAL": "Info",
}
DEFAULT_SEVERITY = "Medium"


class DectraxParser:
    """Parses JSON incident exports from the DECTRAX Cyber Deception platform."""

    def get_scan_types(self):
        return ["DECTRAX Deception Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "DECTRAX Deception Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import active cyber deception telemetry and honeypot incidents from DECTRAX JSON reports."

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        try:
            data = json.loads(content)
        except json.JSONDecodeError as ex:
            msg = f"Invalid DECTRAX JSON report: {ex}"
            raise ValueError(msg) from ex

        incidents = []
        if isinstance(data, list):
            incidents = data
        elif isinstance(data, dict):
            for key in ("incidents", "alerts", "events", "findings"):
                if isinstance(data.get(key), list):
                    incidents = data[key]
                    break
            else:
                if "title" in data or "id" in data:
                    incidents = [data]

        findings = []
        for incident in incidents:
            if not isinstance(incident, dict):
                continue
            finding = self._build_finding(incident, test)
            if finding:
                findings.append(finding)

        return findings

    def _build_finding(self, item, test):
        item_id = str(item.get("id") or item.get("incident_id") or "")
        title = str(item.get("title") or item.get("name") or "DECTRAX Deception Alert").strip()
        raw_sev = str(item.get("severity") or "").strip().upper()
        severity = SEVERITY_MAPPING.get(raw_sev, DEFAULT_SEVERITY)

        description_parts = []
        if raw_desc := item.get("description"):
            description_parts.append(str(raw_desc).strip())
        if deception_type := item.get("deception_type"):
            description_parts.append(f"**Deception Type**: {deception_type}")
        if attacker_ip := item.get("attacker_ip") or item.get("source_ip"):
            description_parts.append(f"**Attacker IP**: {attacker_ip}")
        if target_ip := item.get("target_ip") or item.get("decoy_ip"):
            description_parts.append(f"**Decoy IP**: {target_ip}")
        if protocol := item.get("protocol"):
            description_parts.append(f"**Protocol**: {protocol}")
        if mitre := item.get("mitre_attack_id") or item.get("mitre_attack"):
            description_parts.append(f"**MITRE ATT&CK**: {mitre}")
        if status := item.get("active_defense_status") or item.get("status"):
            description_parts.append(f"**Containment Status**: {status}")

        description = "\n\n".join(description_parts) or "DECTRAX deception sensor interaction detected."
        mitigation = str(item.get("mitigation") or item.get("remediation") or "").strip()

        cwe = 0
        if raw_cwe := item.get("cwe"):
            trimmed = str(raw_cwe).strip().upper().removeprefix("CWE-")
            with suppress(ValueError):
                cwe = int(trimmed)

        mitre_attack = str(item.get("mitre_attack_id") or item.get("mitre_attack") or "").strip()

        finding = Finding(
            test=test,
            title=title,
            severity=severity,
            description=description,
            mitigation=mitigation or "Review decoy sensor logs and enforce firewall containment on attacker IP.",
            cwe=cwe,
            unique_id_from_tool=item_id or None,
            vuln_id_from_tool=mitre_attack or item_id or None,
            active=True,
            false_p=False,
            static_finding=False,
            dynamic_finding=True,
        )

        tags = ["dectrax", "deception"]
        if deception_type:
            tags.append(str(deception_type).lower().replace(" ", "-"))
        for tag in item.get("tags") or []:
            if tag_str := str(tag).strip():
                tags.append(tag_str)
        finding.unsaved_tags = sorted(set(tags))

        if detected_at := item.get("detected_at") or item.get("timestamp"):
            with suppress(ValueError, TypeError):
                finding.date = datetime.fromisoformat(str(detected_at).replace("Z", "+00:00")).date()

        self._attach_endpoint(finding, item)
        return finding

    def _attach_endpoint(self, finding, item):
        host = str(item.get("target_ip") or item.get("decoy_ip") or item.get("attacker_ip") or "").strip()
        if not host:
            return

        with suppress(ValueError):
            ip_address(host)
            protocol = str(item.get("protocol") or "").strip().lower() or None
            port = None
            if raw_port := item.get("target_port") or item.get("port"):
                with suppress(ValueError):
                    port = int(raw_port)

            if locations_enabled():
                finding.unsaved_locations.append(LocationData.url(
                    host=host,
                    protocol=protocol,
                    port=port,
                ))
            else:
                finding.unsaved_endpoints.append(Endpoint(
                    host=host,
                    protocol=protocol,
                    port=port,
                ))
