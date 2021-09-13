
import json
import dateutil.parser

from dojo.models import Finding


class BanditParser(object):

    def get_scan_types(self):
        return ["Bandit Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Bandit Scan"

    def get_description_for_scan_types(self, scan_type):
        return "JSON report format"

    def get_findings(self, filename, test):
        data = json.load(filename)

        dupes = dict()
        if "generated_at" in data:
            find_date = dateutil.parser.parse(data["generated_at"])

        for item in data["results"]:

            findingdetail = "\n".join([
                "**Test Name:** `" + item["test_name"] + "`",
                "**Test ID:** `" + item["test_id"] + "`",
                "**Filename:** `" + item["filename"] + "`",
                "**Line number:** `" + str(item["line_number"]) + "`",
                "**Issue Confidence:** `" + item["issue_confidence"] + "`",
                "**Code:**",
                "```\n" + str(item.get("code")).replace('```', '\\`\\`\\`') + "\n```",
            ])

            sev = item["issue_severity"].title()

            find = Finding(
                title=item["issue_text"],
                test=test,
                description=findingdetail,
                severity=sev,
                file_path=item["filename"],
                line=item["line_number"],
                date=find_date,
                static_finding=True,
                dynamic_finding=False,
                vuln_id_from_tool=":".join([item["test_name"], item["test_id"]]),
                nb_occurences=1,
            )
            # manage confidence
            confidence = self.convert_confidence(item.get('issue_confidence'))
            if confidence:
                find.scanner_confidence = confidence

            dupe_key = item["issue_text"] + item["filename"] + str(item["line_number"])

            if dupe_key in dupes:
                find = dupes[dupe_key]
                find.nb_occurences += find.nb_occurences
            else:
                dupes[dupe_key] = find

        return list(dupes.values())

    def convert_confidence(self, value):
        if "high" == value.lower():
            return 2
        elif "medium" == value.lower():
            return 3
        elif "low" == value.lower():
            return 6
        else:
            return None
