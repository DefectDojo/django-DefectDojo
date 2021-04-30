import json

from dojo.models import Finding


class ESLintParser(object):

    def get_scan_types(self):
        return ["ESLint Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "JSON report format"

    def _convert_eslint_severity_to_dojo_severity(self, eslint_severity):
        if eslint_severity == 2:
            return "High"
        elif eslint_severity == 1:
            return "Medium"
        else:
            return "Info"

    def get_findings(self, filename, test):
        tree = filename.read()
        try:
            data = json.loads(str(tree, 'utf-8'))
        except:
            data = json.loads(tree)

        items = list()
        for item in data:
            findingdetail = ''

            if (len(item["messages"]) == 0):
                continue

            for message in item["messages"]:

                if message["message"] is None:
                    title = str("Finding Not defined")
                else:
                    title = str(message["message"])

                if message["ruleId"] is not None:
                    title = title + ' Test ID: ' + str(message["ruleId"])

                findingdetail += "Filename: " + item["filePath"] + "\n"
                findingdetail += "Line number: " + str(message["line"]) + "\n"

                sev = self._convert_eslint_severity_to_dojo_severity(message["severity"])

                find = Finding(title=title,
                            test=test,
                            description=findingdetail,
                            severity=sev.title(),
                            file_path=item["filePath"],
                            line=message["line"],
                            url='N/A',
                            static_finding=True,
                            mitigation='N/A',
                            impact='N/A')

                items.append(find)
        return items
