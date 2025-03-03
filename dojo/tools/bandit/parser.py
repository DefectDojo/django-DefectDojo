import json

import dateutil.parser

from dojo.models import Finding


class BanditParser:

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Bandit Parser.

        Fields:
        - title: Set to the issue_text outputted by th Bandit Scanner.
        - description: Custom description made from: test_name, test_id, filename, line_number, issue_confidence, and code segments.
        - severity: Set to issue_severity from Bandit Scanner.
        - file_path: Set to filename from Bandit Scanner.
        - line: Set to line from Bandit Scanner.
        - date: Set to date from Bandit Scanner.
        - vuln_id_from_tool: Made from joining test_name and test_id.
        - nb_occurences: Initially set to 1 then updated.
        - scanner_condifence: Set to confidence value if one is returned from the Bandit Scanner.
        """
        return [
            "title",
            "description",
            "severity",
            "file_path",
            "line",
            "date",
            "vuln_id_from_tool",
            "nb_occurences",
            "scanner_confidence",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Bandit Parser.

        Fields:
        - file_path: Set to filename from Bandit Scanner.
        - line: Set to line from Bandit Scanner.
        - vuln_id_from_tool: Made from joining test_name and test_id.
        """
        return [
            "file_path",
            "line",
            "vuln_id_from_tool",
        ]

    def get_scan_types(self):
        return ["Bandit Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Bandit Scan"

    def get_description_for_scan_types(self, scan_type):
        return "JSON report format"

    def get_findings(self, filename, test):
        data = json.load(filename)

        results = []
        if "generated_at" in data:
            find_date = dateutil.parser.parse(data["generated_at"])

        for item in data["results"]:
            findingdetail = "\n".join(
                [
                    "**Test Name:** `" + item["test_name"] + "`",
                    "**Test ID:** `" + item["test_id"] + "`",
                    "**Filename:** `" + item["filename"] + "`",
                    "**Line number:** `" + str(item["line_number"]) + "`",
                    "**Issue Confidence:** `" + item["issue_confidence"] + "`",
                    "**Code:**",
                    "```",
                    str(item.get("code")).replace("```", "\\`\\`\\`"),
                    "```",
                ],
            )

            finding = Finding(
                title=item["issue_text"],
                test=test,
                description=findingdetail,
                severity=item["issue_severity"].title(),
                file_path=item["filename"],
                line=item["line_number"],
                date=find_date,
                static_finding=True,
                dynamic_finding=False,
                vuln_id_from_tool=":".join(
                    [item["test_name"], item["test_id"]],
                ),
                nb_occurences=1,
            )
            # manage confidence
            confidence = self.convert_confidence(item.get("issue_confidence"))
            if confidence:
                finding.scanner_confidence = confidence
            if "more_info" in item:
                finding.references = item["more_info"]

            results.append(finding)

        return results

    def convert_confidence(self, value):
        if value.lower() == "high":
            return 2
        if value.lower() == "medium":
            return 3
        if value.lower() == "low":
            return 6
        return None
