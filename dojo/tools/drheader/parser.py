import json

from dojo.models import Finding


class DrHeaderParser(object):

    def get_scan_types(self):
        return ["DrHeader JSON Importer"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import result of DrHeader JSON output."

    def get_findings(self, filename, test):
        data = json.load(filename)
        items = []
        for item in data:
            findingdetail = ''
            title = "Header : " + item["rule"]
            message = item["message"]
            severity = item["severity"].title()
            find = Finding(title=title,
                           test=test,
                           description=message,
                           severity=severity,
                           static_finding=False)

            items.append(find)
        return items
