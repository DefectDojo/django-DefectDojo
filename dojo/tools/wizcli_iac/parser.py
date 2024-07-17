import json
from dojo.models import Finding

class WizcliIaCParser:
    def get_scan_types(self):
        return ["Wizcli IaC Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Wizcli IaC Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Wizcli IaC Scan results in JSON file format."
