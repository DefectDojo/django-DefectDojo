from dojo.tools.sarif.parser import SarifParser


class SnykCodeParser(SarifParser):

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Snyk Code Parser

        Fields:
        - title: Made using the title from Snyk Code scanner.
        - severity: Set to severity from Snyk Code Scanner converted to Defect Dojo format.
        - severity_justification: Made using severity and CVSS score from Snyk Code Parser.
        - description: Made by combining package name, version, vulnerable version(s), and description from Snyk Code Scanner.
        - mitigation: Set to a string and is added on if more context is available.
        - component_name: Set to component_name from Snyk Code Scanner.
        - component_version: Set to version from Snyk Code Scanner.
        - false_p: Set to false.
        - duplicate: Set to false.
        - out_of_scope: Set to false.
        - impact: Set to same value as severity.
        - static_finding: Set to true.
        - dynamic_finding: Set to false.
        - file_path: Set to from value in the Snyk Code scanner output.
        - vuln_id_from_tool: Set to id from Snyk Code scanner.
        - cvssv3: Set to cvssv3 from Snyk Code scanner if available.
        - cwe: Set to the cwe values outputted from Burp Scanner.
        """
        return [
            "title",
            "severity",
            "severity_justification",
            "description",
            "mitigation",
            "component_name",
            "component_version",
            "false_p",
            "duplicate",
            "out_of_scope",
            "impact",
            "static_finding",
            "dynamic_finding",
            "file_path",
            "vuln_id_from_tool",
            "cvssv3",
            "cwe",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of dedupe fields used in the Snyk Code Parser

        Fields:
        - vuln_id_from_tool: Set to id from Snyk Code scanner.
        - file_path: Set to from value in the Snyk Code scanner output.
        """
        return [
            "vuln_id_from_tool",
            "file_path",
        ]

    def get_scan_types(self):
        return ["Snyk Code Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Snyk Code Scan output can be imported in SARIF JSON format. Generate SARIF reports using: snyk code test --sarif"

    def get_finding_title(self, result, rule, location):
        """Get custom title for Snyk Code with ruleId + file path format"""
        # For Snyk Code, create custom title format
        rule_id = result.get("ruleId", "")
        file_path = ""
        if location:
            phys_loc = location.get("physicalLocation", {})
            artifact_loc = phys_loc.get("artifactLocation", {})
            file_path = artifact_loc.get("uri", "")

        return f"{rule_id}_{file_path}" if rule_id and file_path else rule_id

    def get_finding_description(self, result, rule, location):
        """Custom description formatting for Snyk Code SARIF reports"""
        # Extract Snyk Code specific properties
        props = result.get("properties", {})
        rule_id = result.get("ruleId", "")

        # Build description with Snyk Code specific fields
        description_parts = [
            f"**ruleId**: {rule_id}",
            f"**ruleIndex**: {result.get('ruleIndex', '')}",
            f"**message**: {result.get('message', {}).get('text', '')}",
            f"**score**: {props.get('priorityScore', 0)}",
            f"**isAutofixable**: {props.get('isAutofixable', False)}",
        ]

        # Add location details if available
        if location:
            phys_loc = location.get("physicalLocation", {})
            artifact_loc = phys_loc.get("artifactLocation", {})
            region = phys_loc.get("region", {})

            if artifact_loc.get("uri"):
                description_parts.append(f"**uri**: {artifact_loc.get('uri', '')}")
            if artifact_loc.get("uriBaseId"):
                description_parts.append(f"**uriBaseId**: {artifact_loc.get('uriBaseId', '')}")
            if region.get("startLine"):
                description_parts.append(f"**startLine**: {region.get('startLine', '')}")
            if region.get("endLine"):
                description_parts.append(f"**endLine**: {region.get('endLine', '')}")
            if region.get("startColumn"):
                description_parts.append(f"**startColumn**: {region.get('startColumn', '')}")
            if region.get("endColumn"):
                description_parts.append(f"**endColumn**: {region.get('endColumn', '')}")

        return "\n".join(description_parts)

    def customize_finding(self, finding, result, rule, location):
        """Customize SARIF finding for Snyk Code specific formatting"""
        # Extract Snyk Code specific properties
        props = result.get("properties", {})

        # Use priorityScore for severity calculation
        score = props.get("priorityScore", 0)
        if score <= 399:
            finding.severity = "Low"
        elif score <= 699:
            finding.severity = "Medium"
        elif score <= 899:
            finding.severity = "High"
        else:
            finding.severity = "Critical"
