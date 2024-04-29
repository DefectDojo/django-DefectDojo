import json

from dojo.models import Finding


class ProgpilotParser:
    def get_scan_types(self):
        return ["Progpilot Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Progpilot Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Progpilot JSON vulnerability report format."

    def get_findings(self, filename, test):
        return None
