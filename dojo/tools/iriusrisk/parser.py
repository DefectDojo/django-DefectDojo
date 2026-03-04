import csv
import io
import re

from dojo.models import Finding

SEVERITY_MAPPING = {
    "Very low": "Info",
    "Low": "Low",
    "Medium": "Medium",
    "High": "High",
    "Critical": "Critical",
}


class IriusriskParser:

    def get_scan_types(self):
        return ["IriusRisk Threats Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import IriusRisk threat model CSV exports."

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        reader = csv.DictReader(io.StringIO(content), delimiter=",", quotechar='"')
        findings = []
        for row in reader:
            component = (row.get("Component") or "").strip()
            use_case = (row.get("Use case") or "").strip()
            source = (row.get("Source") or "").strip()
            threat = (row.get("Threat") or "").strip()
            risk_response = (row.get("Risk Response") or "").strip()
            inherent_risk = (row.get("Inherent Risk") or "").strip()
            current_risk = (row.get("Current Risk") or "").strip()
            countermeasure_progress = (row.get("Countermeasure progress") or "").strip()
            weakness_tests = (row.get("Weakness tests") or "").strip()
            countermeasure_tests = (row.get("Countermeasure tests") or "").strip()
            projected_risk = (row.get("Projected Risk") or "").strip()
            owner = (row.get("Owner") or "").strip()
            mitre_reference = (row.get("MITRE reference") or "").strip()
            stride_lm = (row.get("STRIDE-LM") or "").strip()

            # Title: truncate to 500 chars with ellipsis if needed
            title = threat[:497] + "..." if len(threat) > 500 else threat

            severity = SEVERITY_MAPPING.get(current_risk, "Info")

            # Build description with all available fields
            description_parts = [
                f"**Threat:** {threat}",
                f"**Component:** {component}",
                f"**Use Case:** {use_case}",
                f"**Source:** {source}",
                f"**Inherent Risk:** {inherent_risk}",
                f"**Current Risk:** {current_risk}",
                f"**Projected Risk:** {projected_risk}",
                f"**Countermeasure Progress:** {countermeasure_progress}",
                f"**Weakness Tests:** {weakness_tests}",
                f"**Countermeasure Tests:** {countermeasure_tests}",
            ]
            if owner:
                description_parts.append(f"**Owner:** {owner}")
            if stride_lm:
                description_parts.append(f"**STRIDE-LM:** {stride_lm}")
            description = "\n".join(description_parts)

            # Extract CWE from MITRE reference if present
            cwe = None
            references = ""
            if mitre_reference:
                cwe_match = re.match(r"CWE-(\d+)", mitre_reference)
                if cwe_match:
                    cwe = int(cwe_match.group(1))
                else:
                    references = mitre_reference

            finding = Finding(
                test=test,
                title=title,
                severity=severity,
                description=description,
                mitigation=risk_response,
                component_name=component,
                active=current_risk != "Very low",
                static_finding=False,
                dynamic_finding=False,
            )
            if cwe:
                finding.cwe = cwe
            if references:
                finding.references = references
            findings.append(finding)
        return findings
