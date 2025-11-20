
import csv

from dojo.models import Finding, Test


class ZoraParser:

    """Parser for Zora combined CSV export."""

    def get_scan_types(self):
        return ["Zora Parser"]

    def get_label_for_scan_types(self, scan_type):
        return "Zora Parser"

    def get_description_for_scan_types(self, scan_type):
        return "Zora Parser scan results in csv file format."

    def get_findings(self, test: Test, reader: csv.DictReader) -> list[Finding]:
        findings = []

        for row in reader:
            title = row.get("title")
            severity = row.get("severity", "Info").capitalize()
            description = f"**Source**: {row.get('source')}\n"
            description += f"**Image**: {row.get('image')}\n"
            description += f"**ID**: {row.get('id')}\n"
            description += f"**Details**: {row.get('description')}\n"
            if row.get("fixVersion"):
                description += f"**Fix Version**: {row.get('fixVersion')}\n"

            mitigation = row.get("description", "")
            unique_id = f"{row.get('source')}-{row.get('image')}-{row.get('id')}"

            # Determine status
            status = row.get("status", "").upper()
            is_mitigated = status in {"PASS", "OK", "FIXED"}

            finding = Finding(
                title=title,
                description=description,
                severity=severity,
                mitigation=mitigation,
                static_finding=False,
                dynamic_finding=True,
                unique_id_from_tool=unique_id,
                test=test,
                is_mitigated=is_mitigated,
            )
            vuln_id = row.get("id")
            if vuln_id:
                finding.unsaved_vulnerability_ids = [vuln_id]
            findings.append(finding)

        return findings
