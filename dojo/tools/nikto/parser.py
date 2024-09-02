from dojo.tools.nikto.json_parser import NiktoJSONParser
from dojo.tools.nikto.xml_parser import NiktoXMLParser


class NiktoParser:

    """
    Nikto web server scanner - https://cirt.net/Nikto2

    The current parser support 3 sources:
     - XML output (old)
     - new XML output (with nxvmlversion="1.2" type)
     - JSON output

    See: https://github.com/sullo/nikto
    """

    def get_scan_types(self):
        return ["Nikto Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return (
            'XML output (old and new nxvmlversion="1.2" type) or JSON output'
        )

    def get_findings(self, filename, test):
        if filename.name.lower().endswith(".xml"):
            return NiktoXMLParser().process_xml(filename, test)
        if filename.name.lower().endswith(".json"):
            return NiktoJSONParser().process_json(filename, test)
        msg = "Unknown File Format"
        raise ValueError(msg)
