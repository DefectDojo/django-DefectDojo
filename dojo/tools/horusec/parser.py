import json
from datetime import datetime

from dojo.models import Finding
from dojo.tools.parser_test import ParserTest


class HorusecParser(object):
    """Horusec (https://github.com/ZupIT/horusec)"""

    ID = "Horusec"
    CONDIFDENCE = {
        "LOW": 7,  # Tentative
        "MEDIUM": 4,  # Firm
        "HIGH": 1,  # Certain
    }

    def get_scan_types(self):
        return [f"{self.ID} Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "JSON output of Horusec cli."

    def get_findings(self, filename, test):
        data = json.load(filename)
        return [self._get_finding(node) for node in data.get("analysisVulnerabilities")]

    def get_tests(self, scan_type, scan):
        data = json.load(scan)
        test = ParserTest(name=self.ID, type=self.ID, version=data.get("version"))
        test.description = "\n".join(
            [
                f"**Status:** {data.get('status')}",
                "**Errors:**",
                "```",
                data.get("errors"),
                "```",
            ]
        )
        test.findings = [self._get_finding(node) for node in data.get("analysisVulnerabilities")]
        return [test]

    def _get_finding(self, data):
        description = "\n".join([
            data["vulnerabilities"]["details"].split("\n")[-1],
            "**Code:**",
            f"```{data['vulnerabilities']['language']}",
            data["vulnerabilities"]["code"].replace("```", "``````"),
            "```"
        ])
        finding = Finding(
            title=data["vulnerabilities"]["details"].split("\n")[0],
            severity=data["vulnerabilities"]["severity"].title(),
            description=description,
            file_path=data["vulnerabilities"]["file"],
            line=int(data["vulnerabilities"]["line"]),
            scanner_confidence=self.CONDIFDENCE[data["vulnerabilities"]["confidence"]],
        )
        return finding
