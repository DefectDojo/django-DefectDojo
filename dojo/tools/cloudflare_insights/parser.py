import csv
import io
from urllib.parse import urlparse

from dojo.models import Endpoint, Finding


class CloudflareInsightsParser:

    """
    DefectDojo parser for Cloudflare Insights CSV exports.

    Expected columns:
      - severity
      - issue_class
      - subject            (used as Endpoint host; not repeated in description)
      - issue_type
      - scan_performed_on  (ignored)
      - status
      - insight            (optional)
      - detection_method   (optional)
      - risk               (optional)
      - recommended_action (used as mitigation if present)
    """

    def get_scan_types(self):
        return ["Cloudflare Insights"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Cloudflare Insights (CSV export)."

    def _map_severity(self, value):
        normalized = value.strip().lower()
        mapping = {
            "low": "Low",
            "moderate": "Medium",
            "critical": "Critical",
            "high": "High",  # optional: Cloudflare occasionally uses this
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
        host = host.strip().strip("/").strip()

        return host or None

    def _is_inactive_status(self, status: str) -> bool:
        inactive_markers = {"resolved", "mitigated", "closed", "fixed"}
        return bool(status) and status.strip().lower() in inactive_markers

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        reader = csv.DictReader(
            io.StringIO(content),
            delimiter=",",
            quotechar='"',
            skipinitialspace=True,
        )
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
            if issue_type and subject:
                title = f"{issue_type}: {subject}"
            elif issue_type:
                title = issue_type
            elif subject:
                title = subject
            else:
                title = "Cloudflare Insight"
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
                finding.unsaved_endpoints = [Endpoint(host=host, port=None)]
            findings.append(finding)

        return findings
