from dojo.tools.openvas.csv_parser import OpenVASCSVParser
from dojo.tools.openvas.xml_parser import OpenVASXMLParser


class OpenVASParser:
    def get_scan_types(self):
        return ["OpenVAS Parser"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import CSV or XML output of Greenbone OpenVAS report."

    def get_findings(self, filename, test):
        if str(filename.name).endswith(".csv"):
            return OpenVASCSVParser().get_findings(filename, test)
        if str(filename.name).endswith(".xml"):
            return OpenVASXMLParser().get_findings(filename, test)
        return None
