import csv
import io
import json
from urllib.parse import urlparse

from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.url.models import URL


class CloudflareInsightsParser:

    """
    DefectDojo parser for Cloudflare Insights CSV or JSON exports.

    CSV expected columns:
      - severity
      - issue_class
      - subject
      - issue_type
      - status
      - insight (optional)
      - detection_method (optional)
      - risk (optional)
      - recommended_action (optional)

    JSON expected fields:
      - severity
      - issue_class
      - subject
      - issue_type
      - dismissed (maps to status)
      - resolve_text (optional mitigation)
      - risk (optional)
    """

    def get_scan_types(self):
        return ["Cloudflare Insights"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Cloudflare Insights (CSV or JSON export)."

    def _map_severity(self, value):
        normalized = value.strip().lower()
        mapping = {
            "low": "Low",
            "moderate": "Medium",
            "critical": "Critical",
            "high": "High",
        }
        return mapping.get(normalized, "Info")

    def _extract_host_from_subject(self, subject: str) -> str | None:
        if not subject:
            return None
        s = subject.strip()
        if not s:
            return None
        parsed = urlparse(s)
        netloc = parsed.netloc
        if not netloc and ("." in s or ":" in s or s.startswith("localhost")):
            parsed2 = urlparse(f"http://{s}")
            netloc = parsed2.netloc
        host = netloc or s
        if ":" in host:
            host = host.split(":", 1)[0]
        return host.strip().strip("/") or None

    def _is_inactive_status(self, status: str) -> bool:
        inactive_markers = {"resolved", "mitigated", "closed", "fixed"}
        return bool(status) and status.strip().lower() in inactive_markers

    def _parse_csv(self, content: str, test):
        reader = csv.DictReader(io.StringIO(content), delimiter=",", quotechar='"', skipinitialspace=True)
        findings = []
        for row in reader:
            severity_raw = (row.get("severity") or "").strip()
            issue_class = (row.get("issue_class") or "").strip()
            subject = (row.get("subject") or "").strip()
            issue_type = (row.get("issue_type") or "").strip()
            status = (row.get("status") or "").strip()
            insight = (row.get("insight") or "").strip()
            detection_method = (row.get("detection_method") or "").strip()
            risk = (row.get("risk") or "").strip()
            recommended_action = (row.get("recommended_action") or "").strip()

            mapped_severity = self._map_severity(severity_raw)
            title = f"{issue_type}: {subject}" if issue_type and subject else issue_type or subject or "Cloudflare Insight"

            description_parts = []
            if issue_class:
                description_parts.append(f"**Issue class**: {issue_class}")
            if issue_type:
                description_parts.append(f"**Issue type**: {issue_type}")
            if status:
                description_parts.append(f"**Status**: {status}")
            if insight:
                description_parts.append(f"**Insight**: {insight}")
            if detection_method:
                description_parts.append(f"**Detection method**: {detection_method}")
            if risk:
                description_parts.append(f"**Risk**: {risk}")
            description = "\n\n".join(description_parts)

            finding = Finding(
                test=test,
                title=title,
                severity=mapped_severity,
                description=description,
                mitigation=recommended_action,
                references="Not provided!",
                static_finding=False,
                dynamic_finding=True,
            )
            finding.active = not self._is_inactive_status(status)
            host = self._extract_host_from_subject(subject)
            if host:
                if settings.V3_FEATURE_LOCATIONS:
                    finding.unsaved_locations = [URL(host=host, port=None)]
                else:
                    # TODO: Delete this after the move to Locations
                    finding.unsaved_endpoints = [Endpoint(host=host, port=None)]
            findings.append(finding)
        return findings

    def _parse_json(self, content: str, test):
        data = json.loads(content)
        findings = []
        for item in data:
            severity_raw = (item.get("severity") or "").strip()
            issue_class = (item.get("issue_class") or "").strip()
            subject = (item.get("subject") or "").strip()
            issue_type = (item.get("issue_type") or "").strip()
            dismissed = item.get("dismissed", False)
            risk = (item.get("risk") or "").strip()
            recommended_action = (item.get("resolve_text") or "").strip()

            mapped_severity = self._map_severity(severity_raw)
            title = f"{issue_type}: {subject}" if issue_type and subject else issue_type or subject or "Cloudflare Insight"

            description_parts = []
            if issue_class:
                description_parts.append(f"**Issue class**: {issue_class}")
            if issue_type:
                description_parts.append(f"**Issue type**: {issue_type}")
            if risk:
                description_parts.append(f"**Risk**: {risk}")
            description = "\n\n".join(description_parts)

            finding = Finding(
                test=test,
                title=title,
                severity=mapped_severity,
                description=description,
                mitigation=recommended_action,
                references="Not provided!",
                static_finding=False,
                dynamic_finding=True,
            )
            finding.active = not dismissed
            host = self._extract_host_from_subject(subject)
            if host:
                if settings.V3_FEATURE_LOCATIONS:
                    finding.unsaved_locations = [URL(host=host, port=None)]
                else:
                    # TODO: Delete this after the move to Locations
                    finding.unsaved_endpoints = [Endpoint(host=host, port=None)]
            findings.append(finding)
        return findings

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")
        content_strip = content.strip()
        if content_strip.startswith("["):
            return self._parse_json(content_strip, test)
        return self._parse_csv(content_strip, test)
