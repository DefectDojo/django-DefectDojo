import csv
import io
import json

from dojo.models import Finding
from dojo.tools.orca_security.helpers import (
    build_description,
    build_unique_id,
    map_orca_severity,
    parse_date,
    truncate_title,
)


class OrcaSecurityCSVParser:

    """Parse Orca Security CSV alert exports."""

    def parse(self, content):
        reader = csv.DictReader(io.StringIO(content), delimiter=",", quotechar='"')
        findings = []
        for row in reader:
            title_raw = (row.get("Title") or "").strip()
            category = (row.get("Category") or "").strip()
            source = (row.get("Source") or "").strip()
            inventory_name = (row.get("Inventory.Name") or "").strip()
            cloud_account_name = (row.get("CloudAccount.Name") or "").strip()
            orca_score_raw = (row.get("OrcaScore") or "").strip()
            status = (row.get("Status") or "").strip()
            created_at = (row.get("CreatedAt") or "").strip()
            last_seen = (row.get("LastSeen") or "").strip()
            labels_raw = (row.get("Labels") or "").strip()

            # Parse labels from JSON string
            labels = []
            if labels_raw:
                try:
                    labels = json.loads(labels_raw)
                except (json.JSONDecodeError, TypeError):
                    labels = [labels_raw]

            title = truncate_title(title_raw)
            severity = map_orca_severity(orca_score_raw)

            description = build_description(
                title_raw, category, source, inventory_name, cloud_account_name,
                orca_score_raw, status, created_at, last_seen, labels,
            )

            finding = Finding(
                title=title,
                severity=severity,
                description=description,
                static_finding=True,
                dynamic_finding=False,
                component_name=inventory_name or None,
                unique_id_from_tool=build_unique_id(title_raw, source, cloud_account_name),
                date=parse_date(created_at),
            )
            finding.active = status.lower() == "open" if status else True

            findings.append(finding)
        return findings
