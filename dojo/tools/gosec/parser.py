import json
from dojo.models import Finding


class GosecScannerParser(object):
    def __init__(self, filename, test):
        data = json.load(filename)
        dupes = dict()

        for item in data["Issues"]:
            categories = ''
            language = ''
            mitigation = ''
            impact = ''
            references = ''
            findingdetail = ''
            title = ''
            group = ''
            status = ''

            title = item["details"] + "-" + item["rule_id"]

#           Finding details information
            findingdetail += "Filename: " + item["file"] + "\n"
            findingdetail += "Line number: " + str(item["line"]) + "\n"
            findingdetail += "Issue Confidence: " + item["confidence"] + "\n\n"
            findingdetail += "Code:\n"
            findingdetail += item["code"] + "\n"

            sev = item["severity"]
#            mitigation = item["issue_text"]
            mitigation = "coming soon"
#            references = item["test_id"]
            referencesxs = "coming soon"

            dupe_key = title + item["file"] + str(item["line"])

            if dupe_key in dupes:
                find = dupes[dupe_key]
            else:
                dupes[dupe_key] = True

                find = Finding(title=title,
                               test=test,
                               active=False,
                               verified=False,
                               description=findingdetail,
                               severity=sev.title(),
                               numerical_severity=Finding.get_numerical_severity(sev),
                               mitigation=mitigation,
                               impact=impact,
                               references=references,
                               file_path=item["file"],
#                               line = item["line"],
                               url='N/A',
                               static_finding=True)

                dupes[dupe_key] = find
                findingdetail = ''

        self.items = list(dupes.values())
