import json

from django.conf import settings

from dojo.models import Finding
from dojo.tools.locations import LocationData

# cfn-lint grades template correctness, not exploitability: an Error means the template is invalid
# or will fail to deploy, a Warning means it is valid but questionable. The mapping keeps that
# ordering without implying a security rating.
SEVERITIES = {
    "FATAL": "Critical",
    "ERROR": "High",
    "WARNING": "Medium",
    "INFORMATIONAL": "Info",
}
DEFAULT_SEVERITY = "Medium"


class CfnLintParser:

    """Parses the JSON report produced by `cfn-lint --format json`."""

    def get_scan_types(self):
        return ["cfn-lint Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "cfn-lint Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import the JSON report produced by `cfn-lint --format json <template>`."

    def get_findings(self, filename, test):
        data = json.load(filename)
        if not isinstance(data, list):
            msg = f"A cfn-lint JSON report is an array of matches; got a {type(data).__name__}."
            raise TypeError(msg)

        findings = []
        for match in data:
            if not isinstance(match, dict):
                msg = "Every match in a cfn-lint report must be an object."
                raise TypeError(msg)
            findings.append(self.build_finding(match, test))
        return findings

    def build_finding(self, match, test):
        rule = match.get("Rule") or {}
        rule_id = rule.get("Id") or ""
        file_path = match.get("Filename")
        line = ((match.get("Location") or {}).get("Start") or {}).get("LineNumber")

        finding = Finding(
            test=test,
            # The rule's own name is the title, so every instance of a rule groups under one
            # heading; the specific message - which names the offending parameter or property - is
            # the first line of the description.
            title=rule.get("ShortDescription") or rule_id or "cfn-lint match",
            severity=SEVERITIES.get((match.get("Level") or "").upper(), DEFAULT_SEVERITY),
            description=self.build_description(match, rule),
            file_path=file_path,
            line=line,
            static_finding=True,
            dynamic_finding=False,
            vuln_id_from_tool=rule_id or None,
            # cfn-lint's per-match Id is deterministic: the same template produces the same Id on
            # every run, and Ids are distinct within a report, so it is a genuine finding
            # identifier rather than a location hash.
            unique_id_from_tool=match.get("Id") or None,
        )
        if settings.V3_FEATURE_LOCATIONS and file_path:
            finding.unsaved_locations.append(
                LocationData.code(file_path=file_path, line=line),
            )
        return finding

    def build_description(self, match, rule):
        parts = []
        if message := match.get("Message"):
            parts.append(message)
        if description := rule.get("Description"):
            parts.append(f"**Rule:** {description}")
        if rule_id := rule.get("Id"):
            parts.append(f"**Rule ID:** {rule_id}")

        location = match.get("Location") or {}
        if path := location.get("Path"):
            # The template path is what a reader needs to find the offending element, which a line
            # number alone does not give for a deeply nested resource.
            parts.append(f"**Template path:** {'/'.join(str(step) for step in path)}")
        if span := self.format_span(location):
            parts.append(f"**Location:** {span}")
        if source := rule.get("Source"):
            parts.append(f"**Rule documentation:** {source}")
        return "\n".join(parts)

    def format_span(self, location):
        start = location.get("Start") or {}
        end = location.get("End") or {}
        if not start.get("LineNumber"):
            return ""
        span = f"line {start['LineNumber']}, column {start.get('ColumnNumber')}"
        if end.get("LineNumber") and end["LineNumber"] != start["LineNumber"]:
            span += f" to line {end['LineNumber']}"
        return span
