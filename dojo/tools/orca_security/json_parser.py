import json

from dojo.models import Finding
from dojo.tools.orca_security.helpers import (
    build_description,
    build_severity_justification,
    build_unique_id,
    map_orca_severity,
    parse_date,
    truncate_title,
)


class OrcaSecurityJSONParser:

    """Parse Orca Security JSON alert exports."""

    def parse(self, content):
        data = json.loads(content)
        findings = []
        for item in data:
            title_raw = (item.get("Title") or "").strip()
            category = (item.get("Category") or "").strip()
            source = (item.get("Source") or "").strip()
            status = (item.get("Status") or "").strip()
            created_at = (item.get("CreatedAt") or "").strip()
            last_seen = (item.get("LastSeen") or "").strip()
            orca_score = item.get("OrcaScore")
            labels = item.get("Labels") or []

            cloud_account = item.get("CloudAccount") or {}
            cloud_account_name = (cloud_account.get("Name") or "").strip()

            inventory = item.get("Inventory") or {}
            inventory_name = (inventory.get("Name") or "").strip()

            title = truncate_title(title_raw)
            severity = map_orca_severity(orca_score)

            description = build_description(
                title_raw, category, source, inventory_name, cloud_account_name,
                orca_score, status, created_at, last_seen, labels,
            )

            finding = Finding(
                title=title,
                severity=severity,
                description=description,
                severity_justification=build_severity_justification(orca_score),
                static_finding=True,
                dynamic_finding=False,
                service=source or None,
                component_name=inventory_name or None,
                unique_id_from_tool=build_unique_id(cloud_account_name, inventory_name, title_raw),
                date=parse_date(created_at),
            )
            finding.active = status.lower() == "open" if status else True
            if labels:
                finding.unsaved_tags = labels

            findings.append(finding)
        return findings
