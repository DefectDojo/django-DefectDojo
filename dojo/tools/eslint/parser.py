import json

from dojo.models import Finding


class ESLintParser:
    def get_scan_types(self):
        return ["ESLint Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "JSON report format"

    def _convert_eslint_severity_to_dojo_severity(self, eslint_severity):
        if eslint_severity == 2:
            return "High"
        if eslint_severity == 1:
            return "Medium"
        return "Info"

    def get_findings(self, filename, test):
        tree = filename.read()
        try:
            data = json.loads(str(tree, "utf-8"))
        except Exception:
            data = json.loads(tree)

        items = []
        for item in data:
            findingdetail = ""

            if len(item["messages"]) == 0:
                continue

            for message in item["messages"]:
                title = "Finding Not defined" if message["message"] is None else str(message["message"])

                if message["ruleId"] is not None:
                    title = title + " Test ID: " + str(message["ruleId"])

                findingdetail += "Filename: " + item["filePath"] + "\n"
                findingdetail += "Line number: " + str(message["line"]) + "\n"

                sev = self._convert_eslint_severity_to_dojo_severity(
                    message["severity"],
                )

                find = Finding(
                    title=title,
                    test=test,
                    description=findingdetail,
                    severity=sev.title(),
                    file_path=item["filePath"],
                    line=message["line"],
                    url="N/A",
                    static_finding=True,
                    mitigation="N/A",
                    impact="N/A",
                )

                items.append(find)
        return items
