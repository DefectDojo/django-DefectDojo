import json

from dojo.models import Finding


class CheckovParser:

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Checkov Parser.
        Fields:
        - title: Set to check_name outputted from Checkov Scanner.
        - description: Custom description made from: check type, check id, and check name.
        - severity: Set to severity from Checkov Scanner that has been translated into Defect Dojo format.
        - mitigation: Set to severity from Checkov Scanner that has been translated into Defect Dojo format.
        - file_path: Set to file path from Checkov Scanner.
        - line: Set to first line of the file line range from Checkov Scanner.
        - component_name: Set to resource from Checkov Scanner.
        - static_finding: Set to true.
        - dynamic_finding: Set to false.
        """
        return [
            "title",
            "description",
            "severity",
            "mitigation",
            "file_path",
            "line",
            "component_name",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of dedupe fields used in the Checkov Parser

        Fields:
        - title: Set to check_name outputted from Checkov Scanner.
        - line: Set to first line of the file line range from Checkov Scanner.
        - file_path: Set to file path from Checkov Scanner.
        - description: Custom description made from: check type, check id, and check name.

        NOTE: uses legacy dedupe: ['title', 'cwe', 'line', 'file_path', 'description']
        NOTE: cwe is not provided by parser
        """
        return [
            "title",
            "line",
            "file_path",
            "description",
        ]

    def get_scan_types(self):
        return ["Checkov Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Checkov Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON reports of Infrastructure as Code vulnerabilities."

    def get_findings(self, json_output, test):
        findings = []
        if json_output:
            deserialized = self.parse_json(json_output)
            for tree in deserialized:
                check_type = tree.get("check_type", "")
                findings += self.get_items(tree, test, check_type)

        return findings

    def parse_json(self, json_output):
        """
        Parse JSON report.
        Checkov may return only one `check_type` (where the report is just a JSON)
        or more (where the report is an array of JSONs).
        To address all scenarios we force this method to return a list of JSON objects.

        :param json_output: JSON report
        :type json_output: file
        :return: JSON array of objects
        :rtype: list
        """
        try:
            data = json_output.read()
            try:
                deserialized = json.loads(str(data, "utf-8"))
            except BaseException:
                deserialized = json.loads(data)
        except BaseException:
            msg = "Invalid format"
            raise ValueError(msg)

        return (
            [deserialized] if not isinstance(
                deserialized, list) else deserialized
        )

    def get_items(self, tree, test, check_type):
        items = []

        failed_checks = tree.get("results", {}).get("failed_checks", [])
        for node in failed_checks:
            item = get_item(node, test, check_type)
            if item:
                items.append(item)

        return list(items)


def get_item(vuln, test, check_type):
    title = (
        vuln.get("check_name", "check_name not found")
    )
    description = f"Check Type: {check_type}\n"
    if "check_id" in vuln:
        description += f"Check Id: {vuln['check_id']}\n"
    if "check_name" in vuln:
        description += f"{vuln['check_name']}\n"

    if "description" in vuln:
        description += f"\n{vuln['description']}\n"

    if "benchmarks" in vuln:
        bms = vuln['benchmarks'].keys()
        if len(bms) > 0:
            mitigation += f"\nBenchmarks:\n"
            for bm in bms:
                for gl in vuln['benchmarks'][bm]:
                    mitigation += f"- {bm} # {gl['name']} : {gl['description']}\n"

    file_path = vuln.get("file_path", None)
    source_line = None
    if "file_line_range" in vuln:
        lines = vuln["file_line_range"]
        source_line = lines[0]

    resource = None
    if "resource" in vuln:
        resource = vuln["resource"]

    severity = "Medium"
    if "severity" in vuln and vuln["severity"] is not None:
        severity = vuln["severity"].capitalize()

    references = vuln.get("guideline", "")
    return Finding(
        title=title,
        test=test,
        description=description,
        severity=severity,
        mitigation=mitigation,
        references=references,
        file_path=file_path,
        line=source_line,
        component_name=resource,
        static_finding=True,
        dynamic_finding=False,
    )
