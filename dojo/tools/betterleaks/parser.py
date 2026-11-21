from dojo.tools.gitleaks.parser import GitleaksParser


class BetterleaksParser(GitleaksParser):
    def get_scan_types(self):
        return ["Betterleaks Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Betterleaks Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import Betterleaks Scan findings in JSON format."

    def get_findings(self, filename, test):
        """
        Extends the already-existing GitLeaks parser, as BetterLeaks is a
        fork of GitLeaks with the same output format.

        In case of any deviation between the two report formats, this
        method can be implemented as needed.
        """
        return super().get_findings(filename, test)
