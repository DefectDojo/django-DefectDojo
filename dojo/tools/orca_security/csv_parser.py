"""
CSV parser for Orca Security alert exports.

This module handles parsing of Orca Security alerts exported in CSV format.
The CSV export contains one row per alert with columns for all alert metadata.

Expected CSV columns:
    OrcaScore, Title, Category, Inventory, Inventory.Name, CloudAccount,
    CloudAccount.Name, Source, Status, CreatedAt, LastSeen, Labels

Note: The Labels column contains a JSON-encoded array of strings within the CSV.
"""
import csv
import io
import json

from dojo.models import Finding
from dojo.tools.orca_security.helpers import (
    build_description,
    build_severity_justification,
    map_orca_severity,
    parse_date,
    truncate_title,
)


class OrcaSecurityCSVParser:

    """Parse Orca Security CSV alert exports."""

    def parse(self, content):
        """
        Parse CSV content and return a list of Finding objects.

        Args:
            content: String containing the CSV file content

        Returns:
            list[Finding]: List of DefectDojo Finding objects

        """
        reader = csv.DictReader(io.StringIO(content), delimiter=",", quotechar='"')
        findings = []

        for row in reader:
            # Extract all fields from the CSV row
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

            # Parse labels from JSON string embedded in CSV
            # Orca exports labels as a JSON array within the CSV cell
            labels = []
            if labels_raw:
                try:
                    labels = json.loads(labels_raw)
                except (json.JSONDecodeError, TypeError):
                    # If JSON parsing fails, treat the raw string as a single label
                    labels = [labels_raw]

            # Transform fields for DefectDojo
            title = truncate_title(title_raw)
            severity = map_orca_severity(orca_score_raw)

            # Build structured description with all alert metadata
            description = build_description(
                title_raw, category, source, inventory_name, cloud_account_name,
                orca_score_raw, status, created_at, last_seen, labels,
            )

            # Create the Finding object with all mapped fields
            finding = Finding(
                title=title,
                severity=severity,
                description=description,
                # Preserve original OrcaScore in severity_justification
                severity_justification=build_severity_justification(orca_score_raw),
                static_finding=True,  # CSPM scan data is static analysis
                dynamic_finding=False,
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
