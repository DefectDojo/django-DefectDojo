from dojo.tools.veracode.json_parser import VeracodeJSONParser
from dojo.tools.veracode.xml_parser import VeracodeXMLParser


class VeracodeParser:
    def get_scan_types(self):
        return ["Veracode Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Veracode Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Reports can be imported as JSON or XML report formats."
        )

    def get_findings(self, filename, test):
        if filename.name.lower().endswith(".xml"):
            return VeracodeXMLParser().get_findings(filename, test)
        if filename.name.lower().endswith(".json"):
            return VeracodeJSONParser().get_findings(filename, test)
        msg = "Filename extension not recognized. Use .xml or .json"
        raise ValueError(msg)
