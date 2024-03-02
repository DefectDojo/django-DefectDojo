from dojo.tools.cyclonedx.json_parser import CycloneDXJSONParser
from dojo.tools.cyclonedx.xml_parser import CycloneDXXMLParser


class CycloneDXParser(object):
    """CycloneDX is a lightweight software bill of materials (SBOM) standard designed for use in application security
    contexts and supply chain component analysis.
    https://www.cyclonedx.org/
    """

    def get_scan_types(self):
        return ["CycloneDX Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "CycloneDX Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Support CycloneDX XML and JSON report formats (compatible with 1.4)."

    def get_findings(self, file, test):
        if file.name.strip().lower().endswith(".json"):
            return CycloneDXJSONParser()._get_findings_json(file, test)
        else:
            return CycloneDXXMLParser()._get_findings_xml(file, test)
