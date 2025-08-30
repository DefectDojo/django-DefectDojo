from dojo.tools.openvas_v2.csv_parser import OpenVASCSVParserV2
from dojo.tools.openvas_v2.xml_parser import OpenVASXMLParserV2


class OpenVASV2Parser:
    def get_scan_types(self):
        return ["OpenVAS Parser v2"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import CSV or XML output of Greenbone OpenVAS report."

    def get_findings(self, filename, test):
        if str(filename.name).endswith(".csv"):
            return OpenVASCSVParserV2().get_findings(filename, test)
        if str(filename.name).endswith(".xml"):
            return OpenVASXMLParserV2().get_findings(filename, test)
        return None
