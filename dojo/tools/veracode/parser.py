from dojo.tools.veracode.json_parser import VeracodeJSONParser
from dojo.tools.veracode.xml_parser import VeracodeXMLParser
from dojo.tools.veracode.csv_parser import VeracodeCSVParser
from dojo.tools.veracode.json_parser_sca import VeracodeScaParser
import json


class VeracodeParser(object):
    def get_scan_types(self):
        return ["Veracode Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Veracode Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Reports of Veracode Scan can be imported as JSON or XML report formats. \n Reports of Veracode SourceClear Scan can be imported as JSON or CSV report formats."
        )

    def json_structure_mapper(self, filename, test):
        if filename is None:
            return ()
        data = json.load(filename)
        if (data.get("findings", []) or data.get("_embedded", {}).get("findings", [])) != []:
            return VeracodeJSONParser().get_findings(data, test)
        elif data.get("issues", []) or data.get("_embedded", {}).get("issues", []) != []:
            return VeracodeScaParser().get_findings(data, test)

    def get_findings(self, filename, test):
        if filename.name.lower().endswith(".xml"):
            return VeracodeXMLParser().get_findings(filename, test)
        elif filename.name.lower().endswith(".json"):
            return self.json_structure_mapper(filename, test)
        elif filename.name.lower().endswith(".csv"):
            return VeracodeCSVParser().get_findings(filename, test)
        else:
            raise ValueError(
                "Filename extension not recognized. Use .xml or .json"
            )
