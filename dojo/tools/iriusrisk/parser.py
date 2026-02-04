class IriusriskParser:

    def get_scan_types(self):
        return ["IriusRisk Threats Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import IriusRisk threat model CSV exports."

    def get_findings(self, filename, test):
        return []
