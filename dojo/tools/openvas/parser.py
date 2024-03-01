from dojo.tools.openvas.csv_parser import OpenVASCSVParser
from dojo.tools.openvas.xml_parser import OpenVASXMLParser





class OpenVASParser(object):
    
    def read_column_names(self, row):
        column_names = dict()
        index = 0
        for column in row:
            column_names[index] = column
            index += 1
        return column_names

    def get_scan_types(self):
        return ["OpenVAS Parser"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import CSV or XML output of Greenbone OpenVAS report."

    def convert_cvss_score(self, raw_value):
        val = float(raw_value)
        if val == 0.0:
            return "Info"
        elif val < 4.0:
            return "Low"
        elif val < 7.0:
            return "Medium"
        elif val < 9.0:
            return "High"
        else:
            return "Critical"

    def get_findings(self, filename, test):
        if str(filename.name).endswith('.csv'):
            return OpenVASCSVParser().get_findings(filename, test)
        elif str(filename.name).endswith('.xml'):
            return OpenVASXMLParser().get_findings(filename, test)
            