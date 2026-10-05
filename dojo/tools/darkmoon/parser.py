import json
import logging

from dojo.location.feature import locations_enabled
from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData
from dojo.utils import parse_cvss_data

logger = logging.getLogger(__name__)


class DarkmoonParser:

    """
    Parser for the JSON findings report produced by the Darkmoon CLI engine.

    Darkmoon (https://github.com/ASCIT31/Dark-Moon) is an open source (GPL-3.0)
    autonomous AI penetration testing platform: an LLM orchestrates specialist
    agents and offensive tools and attempts to prove each finding with a real
    exploit. The open source CLI emits a JSON findings report; this parser maps
    those findings onto DefectDojo findings, preserving the fields that the
    generic SARIF export cannot carry (exploitation status, CVSS vector, the
    discovering agent, MITRE ATT&CK mapping, ISO 27001 control and the raw
    request/response evidence).
    """

    DEFAULT_SEVERITY = "Info"

    # Darkmoon severities -> DefectDojo severities
    SEVERITY_MAP = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
        "informational": "Info",
    }

    # Darkmoon statuses that mean the finding is no longer open. Darkmoon keeps
    # the finding in the report with one of these statuses once it has been
    # fixed, so they are imported as inactive and mitigated rather than active.
    MITIGATED_STATUSES = {"remediated", "resolved", "closed", "fixed"}

    def get_scan_types(self):
        return ["Darkmoon Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Darkmoon Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import the JSON findings report produced by the Darkmoon CLI "
            "(autonomous AI penetration testing). Keeps the exploitation "
            "status, CVSS vector, discovering agent, MITRE ATT&CK mapping and "
            "raw request/response evidence."
        )

    def get_findings(self, file, test):
        data = json.load(file)

        # Darkmoon writes each campaign's findings as a bare JSON array
        # (vulnerabilities/<campaign_id>.json). Also accept an object that
        # wraps them under "findings" for convenience.
        raw_findings = data if isinstance(data, list) else (data.get("findings") or [])

        return [self._build_finding(item, test) for item in raw_findings]

    def _build_finding(self, item, test):
        title = item.get("title") or "Darkmoon finding"

        severity = self.SEVERITY_MAP.get(
            str(item.get("severity", "")).lower(),
            self.DEFAULT_SEVERITY,
        )

        status = str(item.get("status", "")).lower()
        exploited = status == "exploited"
        mitigated = status in self.MITIGATED_STATUSES

        evidence = item.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {}

        description = self._build_description(item, status, evidence)

        finding = Finding(
            title=title,
            test=test,
            severity=severity,
            description=description,
            static_finding=False,
            dynamic_finding=True,
        )

        if mitigated:
            # remediated / resolved / closed / fixed: Darkmoon confirmed the
            # issue and later saw it fixed, so import it inactive + mitigated.
            finding.active = False
            finding.verified = True
            finding.is_mitigated = True
        else:
            # An exploited finding has been proven with a working exploit, so it
            # is both active and verified; everything else is reported active
            # and left for triage.
            finding.active = True
            finding.verified = exploited

        if item.get("remediation"):
            finding.mitigation = item.get("remediation")

        # CVSS: use the vector when present (DefectDojo validates it and derives
        # the score), otherwise fall back to the numeric score from the report.
        cvss_vector = item.get("cvss_vector")
        if cvss_vector:
            cvss_data = parse_cvss_data(cvss_vector)
            if cvss_data:
                if cvss_data.get("cvssv3"):
                    finding.cvssv3 = cvss_data["cvssv3"]
                if cvss_data.get("cvssv4"):
                    finding.cvssv4 = cvss_data["cvssv4"]
        cvss_score = item.get("cvss_score")
        if cvss_score is not None:
            try:
                finding.cvssv3_score = float(cvss_score)
            except (TypeError, ValueError):
                logger.debug("Ignoring non-numeric cvss_score %s", cvss_score)

        if item.get("cve"):
            finding.unsaved_vulnerability_ids = [str(item.get("cve")).upper()]

        # The component is the plugin/module Darkmoon flagged, or the agent that
        # discovered the issue as a fallback.
        component = item.get("plugin_or_component") or item.get("discovered_by_agent")
        if component:
            finding.component_name = component

        # Reproduction evidence lives in the nested "evidence" object.
        steps = self._build_steps_to_reproduce(evidence)
        if steps:
            finding.steps_to_reproduce = steps
        if evidence.get("raw_request"):
            finding.unsaved_request = evidence.get("raw_request")
        if evidence.get("raw_response"):
            finding.unsaved_response = evidence.get("raw_response")

        # Endpoint (Darkmoon is a dynamic/DAST-style tool). Darkmoon sometimes
        # records a bare path like "/api/login" with no host; DefectDojo
        # endpoints/locations need a host, so those are skipped.
        endpoint_uri = item.get("endpoint")
        if endpoint_uri and not str(endpoint_uri).startswith("/"):
            try:
                if locations_enabled():
                    finding.unsaved_locations = [LocationData.url(url=endpoint_uri)]
                else:
                    # TODO: Delete this after the move to Locations
                    finding.unsaved_endpoints = [Endpoint.from_uri(endpoint_uri)]
            except Exception:
                logger.debug("Could not parse endpoint %s", endpoint_uri)

        finding.unsaved_tags = self._build_tags(item, status)

        return finding

    def _build_description(self, item, status, evidence):
        parts = []
        if item.get("description"):
            parts.append(item.get("description"))

        if status:
            if status == "exploited":
                parts.append(
                    "**Exploitation status:** Exploited "
                    "(Darkmoon proved this finding with a working exploit).",
                )
            else:
                parts.append(f"**Exploitation status:** {status.title()}")

        if item.get("category"):
            parts.append(f"**Category:** {item.get('category')}")
        if item.get("discovered_by_agent"):
            parts.append(f"**Discovered by agent:** {item.get('discovered_by_agent')}")
        if item.get("mitre_attack_id"):
            mitre = item.get("mitre_attack_id")
            if item.get("mitre_attack_name"):
                mitre = f"{mitre} ({item.get('mitre_attack_name')})"
            parts.append(f"**MITRE ATT&CK:** {mitre}")
        if item.get("iso27001_control"):
            parts.append(f"**ISO 27001 control:** {item.get('iso27001_control')}")
        if evidence.get("explanation"):
            parts.append(f"**Evidence:** {evidence.get('explanation')}")

        return "\n\n".join(parts)

    def _build_steps_to_reproduce(self, evidence):
        parts = []
        commands = evidence.get("commands") or []
        if isinstance(commands, str):
            commands = [commands]
        if commands:
            parts.append("**Commands:**\n```\n" + "\n".join(commands) + "\n```")
        logs = evidence.get("logs") or []
        if isinstance(logs, str):
            logs = [logs]
        if logs:
            parts.append("**Logs:**\n```\n" + "\n".join(logs) + "\n```")
        return "\n\n".join(parts)

    def _build_tags(self, item, status):
        tags = []
        if status:
            tags.append(status)
        if item.get("discovered_by_agent"):
            tags.append(item.get("discovered_by_agent"))
        if item.get("category"):
            tags.append(item.get("category"))
        if item.get("mitre_attack_id"):
            tags.append(item.get("mitre_attack_id"))
        return tags
