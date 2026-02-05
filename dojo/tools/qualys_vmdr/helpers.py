"""
Shared helper functions for the Qualys VMDR parser.

This module contains utility functions used by both the QID and CVE parsers
to ensure consistent behavior across input formats.
"""

from dateutil import parser as dateutil_parser

from dojo.models import Endpoint

SEVERITY_MAPPING = {
    "1": "Info",
    "2": "Low",
    "3": "Medium",
    "4": "High",
    "5": "Critical",
}


def map_qualys_severity(severity_value):
    """
    Map Qualys severity (1-5) to DefectDojo severity string.

    Qualys uses a numeric severity scale from 1-5. This function converts
    that to DefectDojo's categorical severity levels.

    Mapping:
        1 -> Info
        2 -> Low
        3 -> Medium
        4 -> High
        5 -> Critical
        Invalid/missing -> Info

    Args:
        severity_value: The Qualys severity value (can be int, string, or None)

    Returns:
        str: DefectDojo severity level ("Info", "Low", "Medium", "High", "Critical")

    """
    if severity_value is None:
        return "Info"
    severity_str = str(severity_value).strip()
    return SEVERITY_MAPPING.get(severity_str, "Info")


def build_severity_justification(severity_value):
    """
    Build severity justification string from Qualys severity.

    Preserves the original numeric severity in the severity_justification field
    so users can see the exact Qualys score that determined the severity level.

    Args:
        severity_value: The Qualys severity value (can be int, string, or None)

    Returns:
        str or None: "Qualys Severity: X" if valid, None otherwise

    """
    if severity_value is None:
        return None
    severity_str = str(severity_value).strip()
    if severity_str in SEVERITY_MAPPING:
        return f"Qualys Severity: {severity_str}"
    return None


def parse_qualys_date(date_string):
    """
    Parse Qualys date format into a Python date object.

    Qualys exports dates in format like "Feb 03, 2026 07:00 AM".
    This function extracts just the date portion for the finding's date field.

    Args:
        date_string: Qualys formatted date string, or None/empty string

    Returns:
        date or None: Python date object if parsing succeeds, None otherwise

    """
    if not date_string or date_string == "'-":
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
             or "Qualys VMDR Finding" if title is empty/None

    """
    if not title:
        return "Qualys VMDR Finding"
    title = title.strip()
    if len(title) <= max_length:
        return title
    return title[: max_length - 3] + "..."


def build_description_qid(row):
    """
    Build a structured markdown description from QID format CSV row.

    Creates a formatted description containing all relevant vulnerability
    metadata. Each field is displayed as a bold label followed by its value.
    Empty/None fields are omitted from the output.

    Args:
        row: Dictionary containing CSV row data

    Returns:
        str: Markdown-formatted description with all non-empty fields

    """
    parts = []

    title = row.get("Title", "")
    if title:
        parts.append(f"**Title:** {title}")

    qid = row.get("QID", "")
    if qid:
        parts.append(f"**QID:** {qid}")

    category = row.get("Category", "")
    if category:
        parts.append(f"**Category:** {category}")

    threat = row.get("Threat", "")
    if threat:
        parts.append(f"**Threat:** {threat}")

    rti = row.get("RTI", "")
    if rti:
        parts.append(f"**RTI:** {rti}")

    os_info = row.get("Operating System", "")
    if os_info:
        parts.append(f"**Operating System:** {os_info}")

    results = row.get("Results", "")
    if results:
        parts.append(f"**Results:** {results}")

    last_detected = row.get("Last Detected", "")
    if last_detected:
        parts.append(f"**Last Detected:** {last_detected}")

    return "\n\n".join(parts) if parts else "No details available."


def build_description_cve(row):
    """
    Build a structured markdown description from CVE format CSV row.

    Creates a formatted description containing all relevant vulnerability
    metadata including CVE-specific fields. Each field is displayed as a
    bold label followed by its value. Empty/None fields are omitted.

    Args:
        row: Dictionary containing CSV row data

    Returns:
        str: Markdown-formatted description with all non-empty fields

    """
    parts = []

    cve = row.get("CVE", "")
    if cve:
        parts.append(f"**CVE:** {cve}")

    cve_desc = row.get("CVE-Description", "")
    if cve_desc:
        parts.append(f"**CVE Description:** {cve_desc}")

    title = row.get("Title", "")
    if title:
        parts.append(f"**Title:** {title}")

    qid = row.get("QID", "")
    if qid:
        parts.append(f"**QID:** {qid}")

    category = row.get("Category", "")
    if category:
        parts.append(f"**Category:** {category}")

    threat = row.get("Threat", "")
    if threat:
        parts.append(f"**Threat:** {threat}")

    rti = row.get("RTI", "")
    if rti:
        parts.append(f"**RTI:** {rti}")

    os_info = row.get("Operating System", "")
    if os_info:
        parts.append(f"**Operating System:** {os_info}")

    results = row.get("Results", "")
    if results:
        parts.append(f"**Results:** {results}")

    last_detected = row.get("Last Detected", "")
    if last_detected:
        parts.append(f"**Last Detected:** {last_detected}")

    return "\n\n".join(parts) if parts else "No details available."


def parse_endpoints(ipv4_field, ipv6_field):
    """
    Parse IP addresses and return list of Endpoint objects.

    Handles comma-separated IP addresses in the IPv4 field and falls back
    to IPv6 if IPv4 is empty.

    Args:
        ipv4_field: Comma-separated IPv4 addresses, or empty string
        ipv6_field: IPv6 address, or empty string

    Returns:
        list[Endpoint]: List of Endpoint objects, one per IP address

    """
    endpoints = []

    if ipv4_field and ipv4_field.strip():
        ips = [ip.strip() for ip in ipv4_field.split(",") if ip.strip()]
        endpoints.extend(Endpoint(host=ip) for ip in ips)
    elif ipv6_field and ipv6_field.strip():
        endpoints.append(Endpoint(host=ipv6_field.strip()))

    return endpoints


def parse_tags(tags_field):
    """
    Split comma-separated tags into a list.

    Args:
        tags_field: Comma-separated tag string, or None/empty string

    Returns:
        list[str]: List of individual tags, empty list if no tags

    """
    if not tags_field or not tags_field.strip():
        return []
    return [tag.strip() for tag in tags_field.split(",") if tag.strip()]


def parse_cvss_score(cvss_field):
    """
    Parse CVSS score field to float.

    Args:
        cvss_field: CVSS score string (e.g., "9.8"), or None/empty

    Returns:
        float or None: Parsed CVSS score, None if invalid or empty

    """
    if not cvss_field or cvss_field == "'-":
        return None
    try:
        return float(cvss_field)
    except (ValueError, TypeError):
        return None
