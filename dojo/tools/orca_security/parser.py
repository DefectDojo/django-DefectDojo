"""
Orca Security parser for DefectDojo.

Orca Security is a cloud security platform that provides agentless security
and compliance for AWS, Azure, GCP, and Kubernetes environments. This parser
imports Orca Security alert exports in CSV or JSON format.

For more information about Orca Security, see: https://orca.security/
"""
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
    "OrcaSecurityParser",
    "build_description",
    "build_unique_id",
    "map_orca_severity",
    "parse_date",
    "truncate_title",
]


class OrcaSecurityParser:

    """Parser for Orca Security alert exports (CSV and JSON)."""

    ID = "Orca Security Alerts"

    def get_scan_types(self):
        """Return the scan type identifier for this parser."""
        return [self.ID]

    def get_label_for_scan_types(self, scan_type):
        """Return the human-readable label for this scan type."""
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        """Return the description shown in the DefectDojo UI."""
        return "Import Orca Security alerts (CSV or JSON export)."

    def get_findings(self, filename, test):
        """
        Parse an Orca Security export file and return findings.

        This method auto-detects the file format (CSV vs JSON) by examining
        the file content. JSON files start with '[' (array), while CSV files
        start with the header row.

        Args:
            filename: File-like object containing the Orca Security export
            test: DefectDojo Test object to associate findings with

        Returns:
            list[Finding]: List of DefectDojo Finding objects

        """
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")
        content_strip = content.strip()

        # Auto-detect format: JSON arrays start with '[', CSV starts with headers
        if content_strip.startswith("["):
            return OrcaSecurityJSONParser().parse(content_strip)
        return OrcaSecurityCSVParser().parse(content_strip)
