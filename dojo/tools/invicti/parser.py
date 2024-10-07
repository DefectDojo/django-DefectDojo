from dojo.tools.netsparker.parser import NetsparkerParser


class InvictiParser(NetsparkerParser):
    def get_scan_types(self):
        return ["Invicti Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Invicti Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Invicti JSON format."

    def get_findings(self, filename, test):
        """
        Extended the NetSparker Parser since the Invicti is the a renamed version of Netsparker.

        If there are deviations from the two report formats in the future, then this
        function can be implemented then.
        """
        return super().get_findings(filename, test)
