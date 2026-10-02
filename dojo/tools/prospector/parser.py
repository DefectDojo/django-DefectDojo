import json

from dojo.models import Finding


class ProspectorParser:

    """
    Parser for Prospector JSON reports.

    Prospector runs several Python analysis tools — pylint, pyflakes, dodgy, bandit and
    others — and reports their messages under a common shape. The tool that raised each
    message is recorded, and the security-oriented sources are given weight while the rest
    stay low, so a hardcoded secret from dodgy is not lost among style warnings.
    """

    # Sources whose findings carry real security weight rather than style.
    SECURITY_SOURCES = {"dodgy", "bandit"}

    def get_scan_types(self):
        return ["Prospector Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Prospector reports in JSON format, generated with 'prospector --output-format json'."

    def get_findings(self, file, test):
        data = json.load(file)
        return [self._to_finding(message, test) for message in data.get("messages", [])]

    def _to_finding(self, message, test):
        source = message.get("source")
        code = message.get("code")
        location = message.get("location") or {}
        path = location.get("path")
        line = location.get("line")

        description = []
        if message.get("message"):
            description.append(message["message"])
        description.extend([
            f"**Tool:** {source}",
            f"**Code:** {code}",
        ])
        if path:
            description.append(f"**Location:** {path}:{line}" if line else f"**Location:** {path}")
        if location.get("function"):
            description.append(f"**Function:** {location['function']}")

        return Finding(
            title=f"{source}: {code} - {message.get('message')}" if message.get("message") else f"{source}: {code}",
            test=test,
            description="\n".join(description),
            severity="High" if source in self.SECURITY_SOURCES else "Low",
            file_path=path,
            line=line,
            vuln_id_from_tool=code,
            static_finding=True,
            dynamic_finding=False,
        )
