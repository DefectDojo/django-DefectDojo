class AlertlogicParser:

    def get_scan_types(self):
        return ["Alert Logic Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Alert Logic vulnerability scan findings (CSV)."

    def get_findings(self, file, test):
        return []
