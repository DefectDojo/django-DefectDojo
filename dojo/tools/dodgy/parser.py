import json

from dojo.models import Finding


class DodgyParser:

    """
    Parser for Dodgy JSON reports.

    Dodgy searches source for hardcoded secrets — passwords, cloud keys, private key
    material, connection strings. It reports no severity, but a match is a credential in
    source control, so findings are imported as High.
    """

    def get_scan_types(self):
        return ["Dodgy Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Dodgy reports in JSON format, generated with 'dodgy' (which writes JSON to stdout)."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for warning in data.get("warnings", []):
            code = warning.get("code")
            message = warning.get("message")
            path = warning.get("path")
            line = warning.get("line")

            description = [message] if message else []
            description.append(f"**Rule:** {code}")
            if path:
                description.append(f"**Location:** {path}:{line}" if line else f"**Location:** {path}")

            findings.append(Finding(
                title=message or code,
                test=test,
                description="\n".join(description),
                # A hardcoded credential in source is treated as High regardless of type.
                severity="High",
                file_path=path,
                line=line,
                vuln_id_from_tool=code,
                mitigation=(
                    "Remove the secret from source, rotate it, and load it from configuration "
                    "or a secrets manager at runtime."
                ),
                static_finding=True,
                dynamic_finding=False,
            ))
        return findings
