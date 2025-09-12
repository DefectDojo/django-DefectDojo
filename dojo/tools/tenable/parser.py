from dojo.tools.tenable.csv_format import TenableCSVParser
from dojo.tools.tenable.xml_format import TenableXMLParser


class TenableParser:

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Tenable CSV Parser

        Fields:
        - title: Made using the name, plugin name, and asset name from Tenable scanner.
        - description: Made by combining synopsis and plugin output from Tenable Scanner.
        - severity: Set to severity from Tenable Scanner converted to Defect Dojo format.
        - mitigation: Set to solution from Tenable Scanner.
        - impact: Set to definition description from Tenable Scanner.
        - cvssv3: If present, set to cvssv3 from Tenable scanner.
        - component_name: If present, set to product name from Tenable Scanner.
        - component_version: If present, set to version from Tenable Scanner.

        Return the list of fields used in the Tenable XML Parser

        Fields:
        - title: Set to plugin name from Tenable scanner.
        - description: Made by combining synopsis element text and plugin output from Tenable Scanner.
        - severity: Set to severity from Tenable Scanner converted to Defect Dojo format.
        - mitigation: Set to solution from Tenable Scanner.
        - impact: Made by combining description element text, cvss score, cvssv3 score, cvss vector, cvss base score, and cvss temporal score from Tenable Scanner.
        - cwe: If present, set to cwe from Tenable scanner.
        - cvssv3: If present, set to cvssv3 from Tenable scanner.
        """
        return [
            "title",
            "description",
            "severity",
            "mitigation",
            "impact",
            "cvssv3",
            "component_name",
            "component_version",
            "cwe",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of dedupe fields used in the Tenable CSV Parser

        Fields:
        - title: Made using the name, plugin name, and asset name from Tenable scanner.
        - severity: Set to severity from Tenable Scanner converted to Defect Dojo format.
        - description: Made by combining synopsis and plugin output from Tenable Scanner.

        NOTE: vulnerability_ids & cwe are not provided by parser

        Return the list of dedupe fields used in the Tenable XML Parser

        Fields:
        - title: Made using the name, plugin name, and asset name from Tenable scanner.
        - severity: Set to severity from Tenable Scanner converted to Defect Dojo format.
        - cwe: If present, set to cwe from Tenable scanner.
        - description: Made by combining synopsis and plugin output from Tenable Scanner.

        NOTE: vulnerability_ids are not provided by parser
        """
        return [
            "title",
            "severity",
            "description",
            "cwe",
        ]

    def get_scan_types(self):
        return ["Tenable Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Tenable Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Reports can be imported as CSV or .nessus (XML) report formats."
        )

    def get_findings(self, filename, test):
        if filename.name.lower().endswith((".xml", ".nessus")):
            return TenableXMLParser().get_findings(filename, test)
        if filename.name.lower().endswith(".csv"):
            return TenableCSVParser().get_findings(filename, test)
        msg = "Filename extension not recognized. Use .xml, .nessus or .csv"
        raise ValueError(msg)
