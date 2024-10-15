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
            "version_name",
        ]

        main_fields_for_test_desc = [
            "app_type",
            "package_name",
            "bundle_id",
            "sdk_name",
            "platform",
        ]

        test_description = ""

        for field in appsec_fields_for_test_desc:

            field_value = str(data.get("appsec", {}).get(field, ""))

            if field_value:
                test_description = "%s  **%s:** %s\n" % (test_description, field, field_value)

        for field in main_fields_for_test_desc:

            field_value = str(data.get(field, ""))

            if field_value:
                test_description = "%s  **%s:** %s\n" % (test_description, field, field_value)

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
            if finding_severity in data.get("appsec", {}):
                for mobsf_finding in data["appsec"][finding_severity]:

                    section = str(mobsf_finding.get("section", ""))
                    title = str(mobsf_finding.get("title", ""))
                    description = str(mobsf_finding.get("description", ""))

                    unique_key = "%s - %s - %s - %s" % (finding_severity, section, title, description)

                    finding = Finding(
                            title=title,
                            cwe=919,  # Weaknesses in Mobile Applications
                            test=test,
                            description="**Category:** %s\n\n%s" % (section, description),
                            severity=finding_severities[finding_severity],
                            references=None,
                            date=find_date,
                            static_finding=True,
                            dynamic_finding=False,
                            nb_occurences=1,
                        )

                    dd_findings[unique_key] = finding

        return list(dd_findings.values())
