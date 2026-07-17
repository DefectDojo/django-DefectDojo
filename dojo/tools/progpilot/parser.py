import json

from django.conf import settings

from dojo.models import Finding
from dojo.tools.locations import LocationData


def _first(value):
    """
    Collapse progpilot taint-source fields to a scalar.

    progpilot reports them as single-element arrays (e.g. source_name=["$sql"],
    source_line=[610]); the location context expects the scalar value.
    """
    if isinstance(value, list):
        return value[0] if value else None
    return value


class ProgpilotParser:
    def get_scan_types(self):
        return ["Progpilot Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Progpilot Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Progpilot JSON vulnerability report format."

    def get_findings(self, filename, test):
        findings = []
        results = json.load(filename)
        for result in results:
            description = ""
            source_name = result.get("source_name", None)
            source_line = result.get("source_line", None)
            source_column = result.get("source_column", None)
            source_file = result.get("source_file", None)
            tainted_flow = result.get("tainted_flow", None)
            sink_name = result.get("sink_name", None)
            sink_line = result.get("sink_line", None)
            sink_column = result.get("sink_column", None)
            sink_file = result.get("sink_file", None)
            vuln_name = result.get("vuln_name", None)
            vuln_cwe = result.get("vuln_cwe", None)
            vuln_id = result.get("vuln_id", None)
            vuln_type = result.get("vuln_type", None)
            vuln_rule = result.get("vuln_rule", None)
            vuln_line = result.get("vuln_line", None)
            vuln_column = result.get("vuln_column", None)
            vuln_file = result.get("vuln_file", None)
            vuln_description = result.get("vuln_description", None)
            description += "**vuln_type:** " + vuln_type + "\n"
            if source_name is not None:
                description += "**source_name:** " + str(source_name) + "\n"
            if source_line is not None:
                description += "**source_line:** " + str(source_line) + "\n"
            if source_column is not None:
                description += "**source_column:** " + str(source_column) + "\n"
            if source_file is not None:
                description += "**source_file:** " + str(source_file) + "\n"
            if tainted_flow is not None:
                description += "**tainted_flow:** " + str(tainted_flow) + "\n"
            if sink_name is not None:
                description += "**sink_name:** " + str(sink_name) + "\n"
            if sink_column is not None:
                description += "**sink_column:** " + str(sink_column) + "\n"
            if vuln_rule is not None:
                description += "**vuln_rule:** " + str(vuln_rule) + "\n"
            if vuln_column is not None:
                description += "**vuln_column:** " + str(vuln_column) + "\n"
            if vuln_description is not None:
                description += "**vuln_description:** " + str(vuln_description) + "\n"
            find = Finding(
                title=vuln_name,
                test=test,
                description=description,
                severity="Medium",
                dynamic_finding=False,
                static_finding=True,
                unique_id_from_tool=vuln_id,
            )
            if sink_line is not None:
                find.line = sink_line
            elif vuln_line is not None:
                find.line = vuln_line
            if sink_file is not None:
                find.file_path = sink_file
            elif vuln_file is not None:
                find.file_path = vuln_file
            if vuln_cwe is not None:
                find.cwe = int(vuln_cwe.split("CWE_")[1])
            if settings.V3_FEATURE_LOCATIONS and find.file_path:
                source_name_scalar = _first(source_name)
                source_file_scalar = _first(source_file)
                source_line_scalar = _first(source_line)
                find.unsaved_locations.append(
                    LocationData.code(
                        file_path=find.file_path,
                        line=find.line,
                        source_object=str(source_name_scalar) if source_name_scalar else "",
                        sink_object=str(sink_name) if sink_name else "",
                        source_file_path=str(source_file_scalar) if source_file_scalar else "",
                        source_line=source_line_scalar if isinstance(source_line_scalar, int) else None,
                    ),
                )
            findings.append(find)
        return findings
