from dojo.tools.openvas.parser_v1.csv_parser import OpenVASCSVParser
from dojo.tools.openvas.parser_v1.xml_parser import OpenVASXMLParser
from dojo.tools.openvas.parser_v2.csv_parser import get_findings_from_csv
from dojo.tools.openvas.parser_v2.xml_parser import get_findings_from_xml


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


class OpenVASParserV2:
    def get_scan_types(self):
        return ["OpenVAS Parser v2"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import CSV or XML output of Greenbone OpenVAS report."

    def get_findings(self, file, test):
        if str(file.name).endswith(".csv"):
            return get_findings_from_csv(file, test)
        if str(file.name).endswith(".xml"):
            return get_findings_from_xml(file, test)
        return None
