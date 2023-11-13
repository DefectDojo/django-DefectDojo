import json
from dojo.models import Finding, Endpoint


class HumbleParser(object):
    """Humble (https://github.com/rfc-st/humble)"""

    def get_scan_types(self):
        return ["Humble Json Importer"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "JSON output of Humble scan."

    def return_finding(self, test, finding, url=None):
        print("TODO")

    def get_findings(self, filename, test):
        items = []
        try:
            data = json.load(filename)
        except ValueError as err:
            data = {}
        if data != {} and data[0].get("url") is not None:
            for item in data:
                url = item["url"]
                for finding in item["report"]:
                    items.append(self.return_finding(test=test, finding=finding, url=url))
            return items
        else:
            for finding in data:
                items.append(self.return_finding(test=test, finding=finding))
            return items
