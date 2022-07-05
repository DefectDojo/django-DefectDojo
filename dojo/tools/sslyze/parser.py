from .parser_json import SSLyzeJSONParser
from .parser_xml import SSLyzeXMLParser


class SslyzeParser(object):
    """SSLyze support JSON and XML"""

    def get_scan_types(self):
        return ["SSLyze Scan (JSON)", "Sslyze Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        if scan_type == "SSLyze Scan (JSON)":
            return "Import JSON report of SSLyze version 3 and higher."
        return "Import XML report of SSLyze version 2 scan."

    def get_findings(self, filename, test):

        if filename is None:
            return list()

        if filename.name.lower().endswith('.xml'):
            return SSLyzeXMLParser().get_findings(filename, test)
        elif filename.name.lower().endswith('.json'):
            return SSLyzeJSONParser().get_findings(filename, test)
        else:
            raise Exception('Unknown File Format')
