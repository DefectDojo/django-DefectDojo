import json
from datetime import datetime

from dojo.models import Finding


class MobSFParser:

    def get_scan_types(self):
        return ["MobSF Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "MobSF Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Export a JSON file using the API, api/v1/report_json."

    def get_findings(self, filename, test):

        tree = filename.read()

        try:
            data = json.loads(str(tree, "utf-8"))
        except:
            data = json.loads(tree)

        if "timestamp" in data:
            find_date = datetime.strptime(data["timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            find_date = datetime.now()

        appsec_fields_for_test_desc = [
            "file_name",
            "hash",
            "security_score",
            "app_name",
            "version_name"
        ]

        main_fields_for_test_desc = [
            "app_type",
            "package_name",
            "bundle_id",
            "sdk_name",
            "platform"
        ]

        test_description = ""

        for field in appsec_fields_for_test_desc:
            if field in data.get("appsec",{}):
                test_description = "{}  **{}:** {}\n".format(test_description, field, data["appsec"][field])

        for field in main_fields_for_test_desc:
            if field in data:
                test_description = "{}  **{}:** {}\n".format(test_description, field, data[field])

        test.description = test_description

        finding_severities = {
            "high": "High",
            "warning": "Medium",
            "info": "Info",
            "secure": "Info",
            "hotspot": "Low",
        }

        dd_findings = {}

        for finding_severity in finding_severities.keys():
            if finding_severity in data.get("appsec",{}):
                for mobsf_finding in data["appsec"][finding_severity]:

                    unique_key = finding_severity + mobsf_finding["section"] + mobsf_finding["title"] + mobsf_finding["description"]

                    finding = Finding(
                            title=mobsf_finding["title"],
                            cwe=919,  # Weaknesses in Mobile Applications
                            test=test,
                            description= "**Category:** " + mobsf_finding["section"] + "\n\n" + mobsf_finding["description"],
                            severity=finding_severities[finding_severity],
                            references=None,
                            date=find_date,
                            static_finding=True,
                            dynamic_finding=False,
                            nb_occurences=1,
                        )

                    dd_findings[unique_key] = finding        

        return list(dd_findings.values())
