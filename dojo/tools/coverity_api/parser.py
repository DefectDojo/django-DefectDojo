import json
from datetime import datetime

from dojo.models import Finding


class CoverityApiParser:
    """Parser that can load data from Synopsys Coverity API"""

    def get_scan_types(self):
        return ["Coverity API"]

    def get_label_for_scan_types(self, scan_type):
        return "Coverity API"

    def get_description_for_scan_types(self, scan_type):
        return "Import Coverity API view data in JSON format (/api/viewContents/issues endpoint)."

    def get_findings(self, file, test):
        tree = json.load(file)

        if "viewContentsV1" not in tree:
            msg = "Report file is not a well-formed Coverity REST view report"
            raise ValueError(msg, file.name)

        items = []
        for issue in tree["viewContentsV1"]["rows"]:
            # get only security findings
            if issue.get("displayIssueKind") != "Security":
                continue

            description_formated = "\n".join(
                [
                    f"**CID:** `{issue.get('cid')}`",
                    f"**Type:** `{issue.get('displayType')}`",
                    f"**Status:** `{issue.get('status')}`",
                    f"**Classification:** `{issue.get('classification')}`",
                ],
            )

            finding = Finding()
            finding.test = test
            finding.title = issue["displayType"]
            finding.severity = self.convert_displayImpact(
                issue.get("displayImpact"),
            )
            finding.description = description_formated
            finding.static_finding = True
            finding.dynamic_finding = False
            finding.unique_id_from_tool = issue.get("cid")

            if "firstDetected" in issue:
                finding.date = datetime.strptime(
                    issue["firstDetected"], "%m/%d/%y",
                ).date()

            if "cwe" in issue and isinstance(issue["cwe"], int):
                finding.cwe = issue["cwe"]

            if "displayFile" in issue:
                finding.file_path = issue["displayFile"]

            if "occurrenceCount" in issue:
                finding.nb_occurences = int(issue["occurrenceCount"])
            else:
                finding.nb_occurences = 1

            if issue.get("status") == "New":
                finding.active = True
                finding.verified = False
            elif issue.get("status") == "Triaged":
                finding.active = True
                finding.verified = True
            elif issue.get("status") == "Fixed":
                finding.active = False
                finding.verified = True
            else:
                if issue.get("classification") == "False Positive":
                    finding.false_p = True
                if "lastTriaged" in issue:
                    ds = issue["lastTriaged"][0:10]
                    finding.mitigated = datetime.strptime(ds, "%Y-%M-%d")
                finding.is_mitigated = True
                finding.active = False
                finding.verified = True

            items.append(finding)

        return items

    def convert_displayImpact(self, val):
        if val is None:
            return "Info"
        if val == "Audit":
            return "Info"
        if val == "Low":
            return "Low"
        if val == "Medium":
            return "Medium"
        if val == "High":
            return "High"
        msg = f"Unknown value for Coverity displayImpact {val}"
        raise ValueError(msg)

    def convert_severity(self, val):
        if val is None:
            return "Info"
        if val == "Unspecified":
            return "Info"
        if val == "Severe":
            return "Critical"
        if val == "Major":
            return "High"
        if val == "Minor":
            return "Medium"
        if val == "New Value":
            return "Info"
        if val == "Various":
            return "Info"
        msg = f"Unknown value for Coverity severity {val}"
        raise ValueError(msg)
