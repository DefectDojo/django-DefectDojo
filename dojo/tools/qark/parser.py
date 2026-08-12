import json

from django.conf import settings

from dojo.models import Finding
from dojo.tools.locations import LocationData

# QARK's three reporting levels.
SEVERITIES = {
    "VULNERABILITY": "High",
    "WARNING": "Medium",
    "INFO": "Info",
}
DEFAULT_SEVERITY = "Medium"

# QARK writes its decompiled output under "<build-path>/qark/", so file_object is an absolute path
# through whatever build directory the run used. Everything up to and including this marker is
# dropped, leaving a stable relative path such as "cfr/com/example/App.java" or
# "AndroidManifest.xml". A path without the marker is reported verbatim rather than guessed at.
BUILD_MARKER = "/qark/"


class QarkParser:

    """Parses the report.json produced by `qark --report-type json`."""

    def get_scan_types(self):
        return ["QARK Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "QARK Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import the report.json produced by `qark --apk <app.apk> --report-type json`."

    def get_findings(self, filename, test):
        data = json.load(filename)
        if not isinstance(data, list):
            msg = f"A QARK JSON report is an array of issues; got a {type(data).__name__}."
            raise TypeError(msg)

        findings = []
        for issue in data:
            if not isinstance(issue, dict):
                msg = "Every issue in a QARK report must be an object."
                raise TypeError(msg)
            findings.append(self.build_finding(issue, test))
        return findings

    def build_finding(self, issue, test):
        name = issue.get("name") or "QARK issue"
        file_path = self.relative_path(issue.get("file_object"))
        line = self.first_line(issue.get("line_number"))

        finding = Finding(
            test=test,
            title=str(name),
            severity=SEVERITIES.get((issue.get("severity") or "").upper(), DEFAULT_SEVERITY),
            description=self.build_description(issue, file_path, line),
            file_path=file_path,
            line=line,
            static_finding=True,
            dynamic_finding=False,
            vuln_id_from_tool=str(name),
        )
        if settings.V3_FEATURE_LOCATIONS and file_path:
            finding.unsaved_locations.append(
                LocationData.code(file_path=file_path, line=line),
            )
        return finding

    def relative_path(self, file_object):
        if not file_object:
            return None
        marker = file_object.rfind(BUILD_MARKER)
        if marker == -1:
            return file_object
        return file_object[marker + len(BUILD_MARKER):] or file_object

    def first_line(self, line_number):
        """QARK reports line_number as a [line, column] pair, or omits it for manifest issues."""
        if isinstance(line_number, list) and line_number:
            first = line_number[0]
            return first if isinstance(first, int) else None
        return line_number if isinstance(line_number, int) else None

    def build_description(self, issue, file_path, line):
        parts = []
        if description := issue.get("description"):
            parts.append(description)
        if category := issue.get("category"):
            parts.append(f"**Category:** {category}")
        if file_path:
            parts.append(f"**File:** {file_path}")
        if line is not None:
            columns = issue.get("line_number")
            column = columns[1] if isinstance(columns, list) and len(columns) > 1 else None
            parts.append(f"**Line:** {line}" + (f", column {column}" if column is not None else ""))

        exploit = issue.get("apk_exploit_dict")
        if isinstance(exploit, dict):
            parts.extend(
                f"**{key.replace('_', ' ').capitalize()}:** {exploit[key]}"
                for key in ("package_name", "tag_name", "exported_enum")
                if exploit.get(key) not in (None, "", [])
            )
        return "\n".join(parts)
