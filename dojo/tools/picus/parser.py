import csv
import io

from dojo.models import Finding

SEVERITY_MAPPING = {
    "Critical": "Critical",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
    "Info": "Info",
    "Informational": "Info",
}


class PicusParser:

    """Parser for Picus Breach and Attack Simulation (BAS) CSV result exports."""

    def get_scan_types(self):
        return ["PICUS Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Picus Breach and Attack Simulation results (CSV)."

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(content), delimiter=",", quotechar='"')

        return [self._build_finding(row, test) for row in reader]

    def _build_finding(self, row, test):
        def get(key):
            return (row.get(key) or "").strip()

        threat_name = get("threatName")
        action_name = get("actionName")
        prevention = get("threatPreventionResult")

        title = f"{threat_name} - {action_name}" if action_name else threat_name
        if len(title) > 500:
            title = title[:497] + "..."

        severity = SEVERITY_MAPPING.get(get("threatSeverity"), "Info")

        description = self._build_description(get)
        mitigation = self._build_mitigation(get)

        finding = Finding(
            test=test,
            title=title,
            severity=severity,
            description=description,
            mitigation=mitigation,
            component_name=get("affectedProducts") or None,
            # In BAS, a finding is active when the attack was NOT blocked.
            active=prevention == "Not Blocked",
            static_finding=False,
            dynamic_finding=True,
        )

        # actionId is Picus's native, run-stable action identifier; it drives
        # hashcode deduplication so the same action matches across re-imports.
        action_id = get("actionId")
        if action_id:
            finding.vuln_id_from_tool = action_id

        cwe = get("cwe")
        if cwe.isdigit():
            finding.cwe = int(cwe)

        cves = [c.strip() for c in get("cve").split(",") if c.strip()]
        if cves:
            finding.unsaved_vulnerability_ids = cves

        tags = self._build_tags(get)
        if tags:
            finding.unsaved_tags = tags

        return finding

    def _build_tags(self, get):
        tags = []
        for key in ("actionMitreTactic", "actionMitreTechnique", "actionMitreSubtechnique", "attackCategory"):
            value = get(key)
            if value and value not in tags:
                tags.append(value)
        return tags

    def _build_mitigation(self, get):
        prevention = get("threatPreventionResult")

        lines = []
        if prevention == "Not Blocked":
            lines.append(
                "The simulated attack was NOT blocked by existing preventive controls. "
                "Review and tune the relevant security controls to block this technique.",
            )
        elif prevention == "Blocked":
            lines.append("The simulated attack was blocked by existing preventive controls.")

        # Which control layer failed (prevent -> log -> alert) tells the analyst
        # which gap to close first.
        posture = [
            ("Prevention", prevention),
            ("Logging", get("threatDetectionLogResult")),
            ("Alerting", get("threatDetectionAlertResult")),
        ]
        posture = [(label, value) for label, value in posture if value]
        if posture:
            lines.append("\n**Control posture**")
            lines.extend(f"- {label}: {value}" for label, value in posture)

        # Links and identifiers from the export that help triage and build a fix.
        references = [
            ("Picus mitigation guidance", get("genericMitigationsTabLink")),
            ("Detection content", get("detectionContentTabLink")),
            ("Action payload output", get("actionPayloadOutputTabLink")),
            ("Action logs", get("actionLogsTabLink")),
        ]
        signature = " ".join(
            part for part in (get("signatureName"), f"({get('signatureId')})" if get("signatureId") else "") if part
        )
        if signature:
            references.append(("Detection signature", signature))
        references = [(label, value) for label, value in references if value]
        if references:
            lines.append("\n**Mitigation & triage references**")
            lines.extend(f"- {label}: {value}" for label, value in references)

        return "\n".join(lines) if lines else None

    def _build_description(self, get):
        fields = [
            ("Threat", "threatName"),
            ("Action", "actionName"),
            ("Action Description", "actionDescription"),
            ("Attack Category", "attackCategory"),
            ("Attack Modules", "attackModules"),
            ("Threat Severity", "threatSeverity"),
            ("Prevention Result", "threatPreventionResult"),
            ("Detection Log Result", "threatDetectionLogResult"),
            ("Detection Alert Result", "threatDetectionAlertResult"),
            ("MITRE Tactic", "actionMitreTactic"),
            ("MITRE Technique", "actionMitreTechnique"),
            ("MITRE Sub-technique", "actionMitreSubtechnique"),
            ("Affected OS", "affectedOs"),
            ("Affected Platforms", "affectedPlatforms"),
            ("Affected Products", "affectedProducts"),
            ("Action Payload", "actionPayload"),
            ("Simulation Run Id", "simulationRunId"),
            ("Action Id", "actionId"),
        ]
        lines = ["| Field | Value |", "| --- | --- |"]
        for label, key in fields:
            value = get(key)
            if value:
                value = value.replace("|", "\\|")
                lines.append(f"| {label} | {value} |")
        return "\n".join(lines)
