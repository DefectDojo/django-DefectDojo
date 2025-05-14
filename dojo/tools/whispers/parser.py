import json

from dojo.models import Finding


class WhispersParser:

    """Identify hardcoded secrets in static structured text"""

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Whispers Parser

        Fields:
        - title: Made by combining message, key, file, and line from Whispers Scanner.
        - description: Made by combining the finding's title with the value from Whispers Scanner.
        - mitigation: Set to a general message for CWE 798.
        - cwe: Set to 798.
        - severity: Set to severity from Whispers scanner that has been converted to Defect Dojo format.
        - file_path: Set to file from Whispers scanner.
        - line: Set to line from Whispers scanner.
        - vuln_id_from_tool: Set to message from Whispers scanner.
        - static_finding: Set to true.
        - dynamic_finding: Set to false.
        """
        return [
            "title",
            "description",
            "mitigation",
            "cwe",
            "severity",
            "file_path",
            "line",
            "vuln_id_from_tool",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of dedupe fields used in the Whispers Parser

        Fields:
        - vuln_id_from_tool: Set to message from Whispers scanner.
        - file_path: Set to file from Whispers scanner.
        - line: Set to line from Whispers scanner.
        """
        return [
            "vuln_id_from_tool",
            "file_path",
            "line",
        ]

    SEVERITY_MAP = {
        # Whispers 2.1
        "BLOCKER": "Critical",
        "CRITICAL": "High",
        "MAJOR": "Medium",
        "MINOR": "Low",
        "INFO": "Info",
        # Whispers 2.2
        "Critical": "Critical",
        "High": "High",
        "Medium": "Medium",
        "Low": "Low",
        "Info": "Info",
    }

    @staticmethod
    def _mask(text, n_plain=4):
        length = len(text)
        if length <= n_plain:
            n_plain = 0

        return text[:n_plain] + ("*" * (length - n_plain))

    def get_scan_types(self):
        return ["Whispers Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Whispers Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Whispers report file can be imported in JSON format (option --json)."

    def get_findings(self, file, test):
        tree = json.load(file)
        findings = []
        for vuln in tree:
            summary = (
                f'Hardcoded {vuln.get("message")} "{vuln.get("key")}" '
                f'in {vuln.get("file")}:{vuln.get("line")}'
            )
            description = f'{summary} `{self._mask(vuln.get("value"))}`'
            findings.append(
                Finding(
                    title=summary,
                    description=description,
                    mitigation=(
                        "Replace hardcoded secret with a placeholder (ie: ENV-VAR). "
                        "Invalidate the leaked secret and generate a new one. "
                        "Supply the new secret through a placeholder to avoid disclosing "
                        "sensitive information in code."
                    ),
                    references="https://cwe.mitre.org/data/definitions/798.html",
                    cwe=798,
                    severity=self.SEVERITY_MAP.get(
                        vuln.get("severity"), "Info",
                    ),
                    file_path=vuln.get("file"),
                    line=int(vuln.get("line")),
                    vuln_id_from_tool=vuln.get("message"),
                    static_finding=True,
                    dynamic_finding=False,
                    test=test,
                ),
            )

        return findings
