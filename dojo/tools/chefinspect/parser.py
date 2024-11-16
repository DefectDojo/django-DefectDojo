import json

from dojo.models import Finding


class ChefInspectParser:
    def get_scan_types(self):
        return ["Chef Inspect Log"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return """Chef Inspect log file"""

    def convert_score(self, raw_value):
        val = float(raw_value)
        if val == 0.0:
            return "Info"
        if val < 0.4:
            return "Low"
        if val < 0.7:
            return "Medium"
        if val < 0.9:
            return "High"
        return "Critical"

    def get_findings(self, file, test):
        lines = file.read()
        result = []
        if isinstance(lines, bytes):
            lines = lines.decode("utf-8")
        loglines = lines.split("\n")
        for line in loglines:
            if len(line) != 0:
                json_object = json.loads(line)
                description = str(json_object.get("description")) + "\n\n"
                description += "batch_runtime: " + str(json_object.get("batch_runtime")) + "\n"
                description += "application_group: " + str(json_object.get("application_group")) + "\n"
                description += "zone: " + str(json_object.get("zone")) + "\n"
                description += "office: " + str(json_object.get("office")) + "\n"
                description += "dc: " + str(json_object.get("dc")) + "\n"
                description += "environment: " + str(json_object.get("environment")) + "\n"
                description += "id: " + str(json_object.get("id")) + "\n"
                description += "control_tags: " + str(json_object.get("control_tags")) + "\n"
                description += "platform: " + str(json_object.get("platform")) + "\n"
                description += "profile: " + str(json_object.get("profile")) + "\n"
                description += "group: " + str(json_object.get("group")) + "\n"
                description += "results: " + str(json_object.get("results")) + "\n"
                result.append(
                    Finding(
                        title=json_object.get("title"),
                        description=description,
                        severity=self.convert_score(json_object.get("impact")),
                        active=True,
                    ),
                )
        return result
