"""
Shared helper functions for the Orca Security parser.

This module contains utility functions used by both the CSV and JSON parsers
to ensure consistent behavior across input formats.
"""
import hashlib

from dateutil import parser as dateutil_parser


def map_orca_severity(score):
    """
    Map OrcaScore (float 0-10) to DefectDojo severity string.

    Orca Security uses a numeric score from 0-10 to indicate severity.
    This function converts that to DefectDojo's categorical severity levels.

    Mapping thresholds:
        - 0 or invalid  -> Info
        - 0.1 - 3.9     -> Low
        - 4.0 - 6.9     -> Medium
        - 7.0 - 8.9     -> High
        - 9.0 - 10.0    -> Critical

    Args:
        score: The OrcaScore value (can be float, int, string, or None)

    Returns:
        str: DefectDojo severity level ("Info", "Low", "Medium", "High", "Critical")

    """
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "Info"
    if score <= 0:
        return "Info"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def build_unique_id(cloud_account_name, inventory_name, title):
    """
    Generate a unique identifier for deduplication.

    Creates a SHA-256 hash from the combination of cloud account, inventory,
    and title fields. This ensures the same alert produces the same ID
    regardless of whether it's imported from CSV or JSON format.

    Args:
        cloud_account_name: The name of the cloud account (e.g., "prod-aws-account")
        inventory_name: The name of the inventory/resource (e.g., "my-s3-bucket")
        title: The alert title (e.g., "Public S3 bucket detected")

    Returns:
        str: 64-character hexadecimal SHA-256 hash

    """
    raw = f"{cloud_account_name}|{inventory_name}|{title}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def build_severity_justification(orca_score):
    """
    Build severity justification string from OrcaScore.

    Preserves the original numeric score in the severity_justification field
    so users can see the exact Orca score that determined the severity level.

    Args:
        orca_score: The OrcaScore value (can be float, int, string, or None)

    Returns:
        str or None: "OrcaScore: X.X" if valid score, None otherwise

    """
    if orca_score is None:
        return None
    try:
        score = float(orca_score)
    except (TypeError, ValueError):
        return None
    else:
        return f"OrcaScore: {score}"


def parse_date(date_string):
    """
    Parse ISO 8601 date string into a Python date object.

    Orca Security exports dates in ISO 8601 format (e.g., "2025-01-15T10:30:00+00:00").
    This function extracts just the date portion for the finding's date field.

    Args:
        date_string: ISO 8601 formatted date string, or None/empty string

    Returns:
        date or None: Python date object if parsing succeeds, None otherwise

    """
    if not date_string:
        return None
    try:
        return dateutil_parser.parse(date_string).date()
    except (ValueError, TypeError):
        return None


def truncate_title(title, max_length=150):
    """
    Truncate title to maximum length with ellipsis suffix.

    DefectDojo has a limit on title length. This function ensures titles
    fit within that limit while indicating truncation occurred.

    Args:
        title: The original title string, or None/empty string
        max_length: Maximum allowed length (default 150 characters)

    Returns:
        str: Original title if within limit, truncated with "..." if over,
             or "Orca Security Alert" if title is empty/None

    """
    if not title:
        return "Orca Security Alert"
    if len(title) <= max_length:
        return title
    return title[: max_length - 3] + "..."


def build_description(title, category, source, inventory_name, cloud_account_name,
                       orca_score, status, created_at, last_seen, labels):
    """
    Build a structured markdown description from alert fields.

    Creates a formatted description containing all relevant alert metadata.
    Each field is displayed as a bold label followed by its value.
    Empty/None fields are omitted from the output.

    Args:
        title: Alert title
        category: Alert category (e.g., "IAM misconfigurations")
        source: Source resource identifier
        inventory_name: Name of the affected inventory/resource
        cloud_account_name: Name of the cloud account
        orca_score: Numeric OrcaScore (0-10)
        status: Alert status (e.g., "open", "closed")
        created_at: ISO 8601 creation timestamp
        last_seen: ISO 8601 last seen timestamp
        labels: List of label strings or single label string

    Returns:
        str: Markdown-formatted description with all non-empty fields

    """
    parts = []
    if title:
        parts.append(f"**Title:** {title}")
    if category:
        parts.append(f"**Category:** {category}")
    if source:
        parts.append(f"**Source:** {source}")
    if inventory_name:
        parts.append(f"**Inventory:** {inventory_name}")
    if cloud_account_name:
        parts.append(f"**Cloud Account:** {cloud_account_name}")
    if orca_score is not None:
        parts.append(f"**Orca Score:** {orca_score}")
    if status:
        parts.append(f"**Status:** {status}")
    if created_at:
        parts.append(f"**Created:** {created_at}")
    if last_seen:
        parts.append(f"**Last Seen:** {last_seen}")
    if labels:
        # Convert list to comma-separated string
        labels_str = ", ".join(str(lbl) for lbl in labels) if isinstance(labels, list) else str(labels)
        if labels_str:
            parts.append(f"**Labels:** {labels_str}")
    return "\n\n".join(parts) if parts else "No details available."
