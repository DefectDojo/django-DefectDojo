from django.conf import settings

from dojo.models import Finding
from dojo.tools.qualys_vmdr.helpers import (
    build_description_qid,
    build_severity_justification,
    map_qualys_severity,
    parse_endpoints,
    parse_locations,
    parse_qualys_csv_content,
    parse_qualys_date,
    parse_tags,
    strip_html,
    truncate_title,
)


class QualysVMDRQIDParser:

    def parse(self, content):
        findings = []
        rows = parse_qualys_csv_content(content)
        for row in rows:
            finding = self._create_finding(row)
            if finding:
                findings.append(finding)
        return findings

    def _create_finding(self, row):
        title = truncate_title(row.get("Title", ""))
        severity = map_qualys_severity(row.get("Severity"))
        severity_justification = build_severity_justification(row.get("Severity"))

        finding = Finding(
            title=title,
            severity=severity,
            severity_justification=severity_justification,
            description=build_description_qid(row),
            mitigation=row.get("Solution", ""),
            impact=strip_html(row.get("Threat", "")),
            unique_id_from_tool=row.get("QID", ""),
            vuln_id_from_tool=row.get("QID", ""),
            date=parse_qualys_date(row.get("First Detected")),
            active=(row.get("Status", "").upper() == "ACTIVE"),
            component_name=row.get("Asset Name", ""),
            service=row.get("Category", ""),
            static_finding=True,
            dynamic_finding=False,
        )

        if settings.V3_FEATURE_LOCATIONS:
            finding.unsaved_locations = parse_locations(
                row.get("Asset IPV4", ""),
                row.get("Asset IPV6", ""),
            )
        else:
            # TODO: Delete this after the move to Locations
            finding.unsaved_endpoints = parse_endpoints(
                row.get("Asset IPV4", ""),
                row.get("Asset IPV6", ""),
            )
        finding.unsaved_tags = parse_tags(row.get("Asset Tags", ""))

        return finding
