from dojo.models import Endpoint, Finding


class CsafParser(object):
    """CSAF Scanner JSON Report"""

    def get_scan_types(self):
        return ["CSAF Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "CSAF Scan"

    def get_description_for_scan_types(self, scan_type):
        return "CSAF JSON report format"

    def get_findings(self, filename, test):
        pass
