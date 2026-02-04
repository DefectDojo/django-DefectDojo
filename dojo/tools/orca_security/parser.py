import hashlib

from dateutil import parser as dateutil_parser

from dojo.tools.orca_security.csv_parser import OrcaSecurityCSVParser
from dojo.tools.orca_security.json_parser import OrcaSecurityJSONParser


def map_orca_severity(score):
    """Map OrcaScore (float 0-10) to DefectDojo severity string."""
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


def build_unique_id(title, source, cloud_account_name):
    """SHA-256 hash of title|source|cloud_account_name for deduplication."""
    raw = f"{title}|{source}|{cloud_account_name}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def parse_date(date_string):
    """Parse ISO 8601 date string, return date object or None."""
    if not date_string:
        return None
    try:
        return dateutil_parser.parse(date_string).date()
    except (ValueError, TypeError):
        return None


def truncate_title(title, max_length=150):
    """Truncate title to max_length, appending '...' if truncated."""
    if not title:
        return "Orca Security Alert"
    if len(title) <= max_length:
        return title
    return title[: max_length - 3] + "..."


def build_description(title, category, source, inventory_name, cloud_account_name,
                       orca_score, status, created_at, last_seen, labels):
    """Build structured markdown description from alert fields."""
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
        if isinstance(labels, list):
            labels_str = ", ".join(str(lbl) for lbl in labels)
        else:
            labels_str = str(labels)
        if labels_str:
            parts.append(f"**Labels:** {labels_str}")
    return "\n\n".join(parts) if parts else "No details available."


class OrcaSecurityParser:
    """Parser for Orca Security alert exports (CSV and JSON)."""

    ID = "Orca Security Alerts"

    def get_scan_types(self):
        return [self.ID]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Orca Security alerts (CSV or JSON export)."

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")
        content_strip = content.strip()
        if content_strip.startswith("["):
            return OrcaSecurityJSONParser().parse(content_strip)
        return OrcaSecurityCSVParser().parse(content_strip)
