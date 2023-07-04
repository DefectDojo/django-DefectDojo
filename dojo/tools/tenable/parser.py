from dojo.tools.tenable.csv_format import TenableCSVParser
from dojo.tools.tenable.xml_format import TenableXMLParser


class TenableParser(object):
    def get_scan_types(self):
        return ["Tenable Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Tenable Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Reports can be imported as CSV or .nessus (XML) report formats."

    def get_findings(self, filename, test):
        if filename.name.lower().endswith(".xml") or filename.name.lower().endswith(".nessus"):
            return TenableXMLParser().get_findings(filename, test)
        elif filename.name.lower().endswith(".csv"):
            return TenableCSVParser().get_findings(filename, test)
        else:
            raise ValueError("Filename extension not recognized. Use .xml, .nessus or .csv")
