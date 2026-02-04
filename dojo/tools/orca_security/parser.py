from dojo.tools.orca_security.csv_parser import OrcaSecurityCSVParser
from dojo.tools.orca_security.helpers import (
    build_description,
    build_unique_id,
    map_orca_severity,
    parse_date,
    truncate_title,
)
from dojo.tools.orca_security.json_parser import OrcaSecurityJSONParser

# Re-export helpers so existing imports from this module still work
__all__ = [
    "build_description",
    "build_unique_id",
    "map_orca_severity",
    "parse_date",
    "truncate_title",
    "OrcaSecurityParser",
]


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
