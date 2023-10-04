import json

import dateutil

from dojo.models import Finding

# https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_Severity.html
SEVERITY_MAPPING = {
    "INFORMATIONAL": "Info",  # No issue was found.
    "LOW": "Low",  # The issue does not require action on its own.
    "MEDIUM": "Medium",  # The issue must be addressed but not urgently.
    "HIGH": "High",  # The issue must be addressed as a priority.
    # The issue must be remediated immediately to avoid it escalating.
    "CRITICAL": "Critical",
}


class AsffParser(object):
    def get_scan_types(self):
        return ["AWS Security Finding Format (ASFF) Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "AWS Security Finding Format (ASFF)"

    def get_description_for_scan_types(self, scan_type):
        return """AWS Security Finding Format (ASFF).
        https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-syntax.html"""

    def get_sources_id(self, item):
        resource_id = ""
        for i in item.get("Resources"):
            resource_id += "source_id: " + i.get("Id") + "\n"
        return resource_id

    def get_description(self, item):
        description = ""
        description = description.join(
            ["ID: ", item.get("Id"), "\n",
             self.get_sources_id(item), "\n",
             "AwsAccountID: ", item.get("AwsAccountId"), "\n",
             item.get("Description")])
        return description

    def get_findings(self, file, test):
        data = json.load(file)
        result = list()
        for item in data:
            if item.get("Remediation"):
                mitigation = item.get("Remediation").get("Recommendation").get("Text")
                references = item.get("Remediation").get("Recommendation").get("Url")
            else:
                mitigation = None
                references = None
            result.append(
                Finding(
                    title=item.get("Title"),
                    description=self.get_description(item),
                    date=dateutil.parser.parse(item.get("CreatedAt")),
                    mitigation=mitigation,
                    references=references,
                    severity=self.get_severity(item.get("Severity")),
                    active=True,  # TODO manage attribute 'RecordState'
                    unique_id_from_tool=item.get("Id"),
                )
            )
        return result

    def get_severity(self, data):
        if data.get("Label"):
            return SEVERITY_MAPPING[data.get("Label")]
        elif isinstance(data.get("Normalized"), int):
            # 0 - INFORMATIONAL
            # 1–39 - LOW
            # 40–69 - MEDIUM
            # 70–89 - HIGH
            # 90–100 - CRITICAL
            if data.get("Normalized") > 89:
                return "Critical"
            elif data.get("Normalized") > 69:
                return "High"
            elif data.get("Normalized") > 39:
                return "Medium"
            elif data.get("Normalized") > 0:
                return "Low"
            else:
                return "Info"
        return None
