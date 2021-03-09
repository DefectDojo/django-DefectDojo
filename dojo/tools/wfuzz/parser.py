import json

from dojo.models import Finding


class WFuzzParser(object):

    def get_scan_types(self):
        return ["WFuzz"]

    def get_label_for_scan_types(self, scan_type):
        return "WFuzz JSON report"

    def get_findings(self, file, test):
        dupes = {}

        return list(dupes.values())

