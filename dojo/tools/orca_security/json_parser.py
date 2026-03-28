"""
JSON parser for Orca Security alert exports.

This module handles parsing of Orca Security alerts exported in JSON format.
The JSON export is an array of alert objects with nested structures for
CloudAccount and Inventory fields.

Expected JSON structure:
    [
        {
            "Title": "...",
            "OrcaScore": 5.1,
            "Category": "...",
            "Source": "...",
            "Status": "open",
            "CreatedAt": "2025-01-15T10:30:00+00:00",
            "LastSeen": "2025-02-01T12:00:00+00:00",
            "Labels": ["label1", "label2"],
            "CloudAccount": {"Name": "..."},
            "Inventory": {"Name": "..."}
        },
        ...
    ]
"""
import json

from dojo.models import Finding
from dojo.tools.orca_security.helpers import (
    build_description,
    build_severity_justification,
    map_orca_severity,
    parse_date,
    truncate_title,
)


class OrcaSecurityJSONParser:

    """Parse Orca Security JSON alert exports."""

    def parse(self, content):
        """
        Parse JSON content and return a list of Finding objects.

        Args:
            content: String containing the JSON file content (array of alerts)

        Returns:
            list[Finding]: List of DefectDojo Finding objects

        """
        data = json.loads(content)
        findings = []

        for item in data:
            # Extract top-level fields
            title_raw = (item.get("Title") or "").strip()
            category = (item.get("Category") or "").strip()
            source = (item.get("Source") or "").strip()
            status = (item.get("Status") or "").strip()
            created_at = (item.get("CreatedAt") or "").strip()
            last_seen = (item.get("LastSeen") or "").strip()
            orca_score = item.get("OrcaScore")  # Keep as numeric, not string
            labels = item.get("Labels") or []  # Already a list in JSON

            # Extract nested fields from CloudAccount and Inventory objects
            cloud_account = item.get("CloudAccount") or {}
            cloud_account_name = (cloud_account.get("Name") or "").strip()

            inventory = item.get("Inventory") or {}
            inventory_name = (inventory.get("Name") or "").strip()

            # Transform fields for DefectDojo
            title = truncate_title(title_raw)
            severity = map_orca_severity(orca_score)

            # Build structured description with all alert metadata
            description = build_description(
                title_raw, category, source, inventory_name, cloud_account_name,
                orca_score, status, created_at, last_seen, labels,
            )

            # Create the Finding object with all mapped fields
            finding = Finding(
                title=title,
                severity=severity,
                description=description,
                # Preserve original OrcaScore in severity_justification
                severity_justification=build_severity_justification(orca_score),
                static_finding=True,  # CSPM scan data is static analysis
                dynamic_finding=False,
                service=source or None,  # Source identifies the cloud resource/service
                component_name=inventory_name or None,  # Inventory is the specific resource
                date=parse_date(created_at),
            )

            # Set active status based on Orca's status field
            # "open" alerts are active, all other statuses (closed, resolved, etc.) are inactive
            finding.active = status.lower() == "open" if status else True

            # Store labels as tags for searchability in DefectDojo
            if labels:
                finding.unsaved_tags = labels

            findings.append(finding)

        return findings
