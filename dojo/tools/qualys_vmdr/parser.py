"""
Qualys VMDR parser for DefectDojo.

Qualys VMDR (Vulnerability Management, Detection, and Response) provides
comprehensive vulnerability assessment and management. This parser imports
Qualys VMDR exports in CSV format (QID or CVE variants).

For more information about Qualys VMDR, see:
https://www.qualys.com/apps/vulnerability-management-detection-response/
"""

from dojo.tools.qualys_vmdr.cve_parser import QualysVMDRCVEParser
from dojo.tools.qualys_vmdr.qid_parser import QualysVMDRQIDParser


class QualysVMDRParser:

    """Parser for Qualys VMDR vulnerability exports (CSV format)."""

    def get_scan_types(self):
        """Return the scan type identifier for this parser."""
        return ["Qualys VMDR"]

    def get_label_for_scan_types(self, scan_type):
        """Return the human-readable label for this scan type."""
        return "Qualys VMDR"

    def get_description_for_scan_types(self, scan_type):
        """Return the description shown in the DefectDojo UI."""
        return "Import Qualys VMDR vulnerability exports (CSV format, QID or CVE)."

    def get_findings(self, filename, test):
        """
        Parse a Qualys VMDR export file and return findings.

        This method auto-detects the file format (QID vs CVE) by examining
        the CSV header row. QID format has "QID" as the first column, while
        CVE format has "CVE" as the first column.

        Args:
            filename: File-like object containing the Qualys VMDR export
            test: DefectDojo Test object to associate findings with

        Returns:
            list[Finding]: List of DefectDojo Finding objects

        """
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        lines = content.split("\n")
        if len(lines) < 4:
            return []

        header_line = lines[3]

        if header_line.startswith(('"CVE,', "CVE,")):
            return QualysVMDRCVEParser().parse(content)
        return QualysVMDRQIDParser().parse(content)
