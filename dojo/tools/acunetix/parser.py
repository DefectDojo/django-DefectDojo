from dojo.tools.acunetix.parse_acunetix360_json import AcunetixJSONParser
from dojo.tools.acunetix.parse_acunetix_xml import AcunetixXMLParser


class AcunetixParser:

    """Parser for Acunetix XML files and Acunetix 360 JSON files."""

    def get_fields(self, filename) -> list[str]:
        if ".xml" in str(filename):
            return AcunetixXMLParser().get_fields(self)
        if ".json" in str(filename):
            return AcunetixJSONParser().get_fields(self)
        return None

    def get_dedupe_fields(self, filename) -> list[str]:
        if ".xml" in str(filename):
            return AcunetixXMLParser().get__dedupe_fields(self)
        if ".json" in str(filename):
            return AcunetixJSONParser().get_dedupe_fields(self)
        return None

    def get_scan_types(self):
        return ["Acunetix Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Acunetix Scanner"

    def get_description_for_scan_types(self, scan_type):
        return "Acunetix Scanner in XML format or Acunetix 360 Scanner in JSON format"

    def get_findings(self, filename, test):
        if ".xml" in str(filename):
            return AcunetixXMLParser().get_findings(filename, test)
        if ".json" in str(filename):
            return AcunetixJSONParser().get_findings(filename, test)
        return None
