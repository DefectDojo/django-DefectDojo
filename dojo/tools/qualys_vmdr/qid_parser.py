"""
QID format parser for Qualys VMDR exports.

This module handles the QID-centric CSV export format where the primary
identifier is the Qualys QID (vulnerability ID).
"""

import csv
import io

from dojo.models import Finding
from dojo.tools.qualys_vmdr.helpers import (
    build_description_qid,
    build_severity_justification,
    map_qualys_severity,
    parse_endpoints,
    parse_qualys_date,
    parse_tags,
    truncate_title,
)


class QualysVMDRQIDParser:

    """Parse Qualys VMDR QID format exports."""

    def parse(self, content):
        """
        Parse QID format CSV content and return findings.

        Args:
            content: String containing the full CSV content

        Returns:
            list[Finding]: List of DefectDojo Finding objects

        """
        findings = []

        lines = content.split("\n")
        if len(lines) < 4:
            return findings

        csv_content = "\n".join(lines[3:])
        reader = csv.DictReader(io.StringIO(csv_content))

        for row in reader:
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
            description=build_description_qid(row),
            mitigation=row.get("Solution", ""),
            impact=row.get("Threat", ""),
            unique_id_from_tool=row.get("QID", ""),
            date=parse_qualys_date(row.get("First Detected")),
            active=(row.get("Status", "").upper() == "ACTIVE"),
            component_name=row.get("Asset Name", ""),
            service=row.get("Category", ""),
            static_finding=True,
            dynamic_finding=False,
        )

        finding.unsaved_endpoints = parse_endpoints(
            row.get("Asset IPV4", ""),
            row.get("Asset IPV6", ""),
        )
        finding.unsaved_tags = parse_tags(row.get("Asset Tags", ""))

        return finding
