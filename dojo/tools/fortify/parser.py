from dojo.tools.fortify.fpr_parser import FortifyFPRParser
from dojo.tools.fortify.xml_parser import FortifyXMLParser


class FortifyParser:
    def get_scan_types(self):
        return ["Fortify Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import Findings in FPR or XML file format."

    def get_findings(self, filename, test):
        if str(filename.name).endswith(".xml"):
            return FortifyXMLParser().parse_xml(filename, test)
        if str(filename.name).endswith(".fpr"):
            return FortifyFPRParser().parse_fpr(filename, test)
        msg = "Filename extension not recognized. Use .xml or .fpr"
        raise ValueError(msg)
