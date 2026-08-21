import json

from dojo.location.feature import locations_enabled
from dojo.models import Finding
from dojo.tools.locations import LocationData

# Infer's four reporting levels.
SEVERITIES = {
    "ERROR": "High",
    "WARNING": "Medium",
    "INFO": "Low",
    "ADVICE": "Info",
}
DEFAULT_SEVERITY = "Medium"


class InferParser:

    """Parses the report.json Infer writes into its results directory."""

    def get_scan_types(self):
        return ["Infer Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Infer Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import the report.json produced by `infer run -- <build command>`."

    def get_findings(self, filename, test):
        data = json.load(filename)
        if not isinstance(data, list):
            msg = f"An Infer report.json is a JSON array of issues; got a {type(data).__name__}."
            raise TypeError(msg)

        findings = []
        for issue in data:
            if not isinstance(issue, dict):
                msg = "Every issue in an Infer report must be an object."
                raise TypeError(msg)
            findings.append(self.build_finding(issue, test))
        return findings

    def build_finding(self, issue, test):
        bug_type = issue.get("bug_type") or ""
        file_path = issue.get("file")
        line = issue.get("line")

        finding = Finding(
            test=test,
            title=issue.get("bug_type_hum") or bug_type or "Infer issue",
            severity=SEVERITIES.get((issue.get("severity") or "").upper(), DEFAULT_SEVERITY),
            description=self.build_description(issue),
            file_path=file_path,
            line=line,
            static_finding=True,
            dynamic_finding=False,
            vuln_id_from_tool=bug_type or None,
            # Infer's own "hash" is deliberately NOT used as unique_id_from_tool. It identifies the
            # bug site rather than the individual issue, so two distinct reports at one line - the
            # same dereference reached by two different null origins, say - share a hash. Keying on
            # it would silently discard one of them. The qualifier, which does differ, is in the
            # description and so participates in the hash_code instead.
        )
        if locations_enabled() and file_path:
            finding.unsaved_locations.append(
                LocationData.code(file_path=file_path, line=line),
            )
        return finding

    def build_description(self, issue):
        parts = []
        if qualifier := issue.get("qualifier"):
            parts.append(qualifier)
        if category := issue.get("category"):
            parts.append(f"**Category:** {category}")
        if bug_type := issue.get("bug_type"):
            parts.append(f"**Issue type:** {bug_type}")
        if procedure := issue.get("procedure"):
            start = issue.get("procedure_start_line")
            parts.append(
                f"**Procedure:** {procedure}" + (f" (starts at line {start})" if start else ""),
            )
        if (column := issue.get("column")) is not None:
            parts.append(f"**Column:** {column}")

        if trace := self.format_trace(issue.get("bug_trace")):
            parts.append("**Trace:**\n" + trace)

        # Kept for traceability back to the report; see build_finding for why it is not the key.
        if issue_hash := issue.get("hash"):
            parts.append(f"**Infer hash:** {issue_hash}")
        return "\n".join(parts)

    def format_trace(self, trace):
        """Render Infer's explanation of how the issue is reached."""
        rows = []
        for step in trace or []:
            if not isinstance(step, dict):
                continue
            where = step.get("filename") or ""
            if (line_number := step.get("line_number")) is not None:
                where = f"{where}:{line_number}" if where else str(line_number)
            description = step.get("description") or ""
            rows.append(f"- {where} {description}".rstrip() if where else f"- {description}")
        return "\n".join(rows)
