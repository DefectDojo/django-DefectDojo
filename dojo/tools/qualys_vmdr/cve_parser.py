"""
CVE format parser for Qualys VMDR exports.

This module handles the CVE-centric CSV export format where findings
include CVE identifiers and CVSS scores from NVD.
"""

from dojo.models import Finding
from dojo.tools.qualys_vmdr.helpers import (
    build_description_cve,
    build_severity_justification,
    map_qualys_severity,
    parse_cvss_score,
    parse_endpoints,
    parse_qualys_csv_content,
    parse_qualys_date,
    parse_tags,
    truncate_title,
)


class QualysVMDRCVEParser:

    """Parse Qualys VMDR CVE format exports."""

    def parse(self, content):
        """
        Parse CVE format CSV content and return findings.

        Args:
            content: String containing the full CSV content

        Returns:
            list[Finding]: List of DefectDojo Finding objects

        """
        findings = []

        rows = parse_qualys_csv_content(content, skip_metadata_lines=3)

        for row in rows:
            finding = self._create_finding(row)
            if finding:
                findings.append(finding)

        return findings

    def _create_finding(self, row):
        """
        Create a Finding object from a CSV row.

        Args:
            row: Dictionary containing CSV row data

        Returns:
            Finding: DefectDojo Finding object

        """
        title = truncate_title(row.get("Title", ""))
        severity = map_qualys_severity(row.get("Severity"))
        severity_justification = build_severity_justification(row.get("Severity"))

        finding = Finding(
            title=title,
            severity=severity,
            severity_justification=severity_justification,
            description=build_description_cve(row),
            mitigation=row.get("Solution", ""),
            impact=row.get("Threat", ""),
            unique_id_from_tool=row.get("QID", ""),
            vuln_id_from_tool=row.get("CVE", ""),
            date=parse_qualys_date(row.get("First Detected")),
            active=(row.get("Status", "").upper() == "ACTIVE"),
            component_name=row.get("Asset Name", ""),
            service=row.get("Category", ""),
            static_finding=True,
            dynamic_finding=False,
        )

        cvss_score = parse_cvss_score(row.get("CVSSv3.1 Base (nvd)"))
        if cvss_score is not None:
            finding.cvssv3_score = cvss_score

        finding.unsaved_endpoints = parse_endpoints(
            row.get("Asset IPV4", ""),
            row.get("Asset IPV6", ""),
        )
        finding.unsaved_tags = parse_tags(row.get("Asset Tags", ""))

        return finding
