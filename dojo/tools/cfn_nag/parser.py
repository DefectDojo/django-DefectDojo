import json

from dojo.location.feature import locations_enabled
from dojo.models import Finding
from dojo.tools.locations import LocationData

# cfn-nag has exactly two outcomes. A FAIL is a rule the template breaks; a WARN is one it may break
# depending on intent, which is why it is not treated as equivalent.
SEVERITIES = {
    "FAIL": "High",
    "WARN": "Medium",
}
DEFAULT_SEVERITY = "Medium"


class CfnNagParser:

    """Parses the JSON report produced by `cfn_nag_scan --output-format json`."""

    def get_scan_types(self):
        return ["cfn-nag Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "cfn-nag Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import the JSON report produced by "
            "`cfn_nag_scan --input-path <path> --output-format json`."
        )

    def get_findings(self, filename, test):
        data = json.load(filename)
        if not isinstance(data, list):
            msg = f"A cfn-nag JSON report is an array of scanned files; got a {type(data).__name__}."
            raise TypeError(msg)

        findings = []
        for entry in data:
            if not isinstance(entry, dict):
                msg = "Every entry in a cfn-nag report must be an object."
                raise TypeError(msg)
            template = self.template_path(entry.get("filename"))
            results = entry.get("file_results") or {}
            for violation in results.get("violations") or []:
                findings.extend(self.build_findings(violation, template, test))
        return findings

    def template_path(self, filename):
        """cfn-nag echoes the path it was given; a leading "./" from a relative scan is dropped."""
        if not filename:
            return None
        return filename.removeprefix("./")

    def build_findings(self, violation, template, test):
        """
        One finding per offending RESOURCE, not per violation.

        A single cfn-nag violation can cover several resources - one unencrypted queue rule fires
        once for every queue - reporting them in parallel `logical_resource_ids` and `line_numbers`
        lists. Emitting one finding for the violation would mean fixing one resource could not close
        it, so the two lists are paired by index and each resource becomes its own finding.
        """
        resources = [r for r in violation.get("logical_resource_ids") or [] if r]
        lines = violation.get("line_numbers") or []

        if not resources:
            # A violation that names no resource still has to be reported; it anchors to the first
            # line cfn-nag gave, if any.
            return [self.build_finding(violation, template, None, self.line_at(lines, 0), test)]

        return [
            self.build_finding(violation, template, resource, self.line_at(lines, index), test)
            for index, resource in enumerate(resources)
        ]

    def line_at(self, lines, index):
        """The lists are index-aligned; a short line list falls back to the first entry."""
        if index < len(lines) and isinstance(lines[index], int):
            return lines[index]
        if lines and isinstance(lines[0], int):
            return lines[0]
        return None

    def build_finding(self, violation, template, resource, line, test):
        violation_id = violation.get("id") or ""

        finding = Finding(
            test=test,
            # The message is the rule's own wording and is the same for every resource it fires on,
            # which makes it a stable title; the resource is what distinguishes the findings.
            title=violation.get("message") or violation.get("name") or "cfn-nag violation",
            severity=SEVERITIES.get((violation.get("type") or "").upper(), DEFAULT_SEVERITY),
            description=self.build_description(violation, resource),
            file_path=template,
            line=line,
            component_name=resource or None,
            static_finding=True,
            dynamic_finding=False,
            vuln_id_from_tool=violation_id or None,
        )
        if locations_enabled() and template:
            finding.unsaved_locations.append(
                LocationData.code(file_path=template, line=line),
            )
        return finding

    def build_description(self, violation, resource):
        parts = []
        if message := violation.get("message"):
            parts.append(message)
        if resource:
            parts.append(f"**Resource:** {resource}")
        if violation_id := violation.get("id"):
            parts.append(f"**Rule ID:** {violation_id}")
        if name := violation.get("name"):
            parts.append(f"**Rule:** {name}")
        if violation_type := violation.get("type"):
            parts.append(f"**Result:** {violation_type}")
        if element_types := [e for e in violation.get("element_types") or [] if e]:
            parts.append(f"**Element types:** {', '.join(element_types)}")

        # When a rule covered more than one resource, say so, so the reader knows sibling findings
        # exist for the same rule.
        others = [r for r in violation.get("logical_resource_ids") or [] if r and r != resource]
        if others:
            parts.append(f"**Also reported for:** {', '.join(others)}")
        return "\n".join(parts)
