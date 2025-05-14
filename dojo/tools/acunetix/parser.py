from dojo.tools.acunetix.parse_acunetix360_json import AcunetixJSONParser
from dojo.tools.acunetix.parse_acunetix_xml import AcunetixXMLParser


class AcunetixParser:

    """Parser for Acunetix XML files and Acunetix 360 JSON files."""

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Acunetix XML Parser.

        Fields:
        - title: Set to the name outputted by the Acunetix XML Scanner.
        - severity: Set to severity from Acunetix XML Scanner converted into Defect Dojo format.
        - description: Set to description, Details, and TechnivalDetails variables outputted from Acunetix XML Scanner.
        - false_p: Set to True/False based on Defect Dojo standards.
        - static_finding: Set to True by default and updated to False if requests are present.
        - dynamic_finding: Set to False by default and updated to True if requests are present.
        - nb_occurences: Set to 1 and increased based on presence of occurences.
        - impact: Set to impact outputted from Acunetix XML Scanner if it is present.
        - mitigation: Set to Recommendation outputted from Acunetix XML Scanner if it is present.
        - date: Set to StartTime outputted from Acunetix XML Scanner if it is present.
        - cwe: Set to converted cwe outputted from Acunetix XML Scanner if it is present.
        - cvssv3: Set to converted cvssv3 values outputted from Acunetix XML Scanner if it is present.

        Return the list of fields used in the Acunetix 360 Parser.

        Fields:
        - title: Set to the name outputted by the Acunetix 360 Scanner.
        - description: Set to Description variable outputted from Acunetix 360 Scanner.
        - severity: Set to severity from Acunetix 360 Scanner converted into Defect Dojo format.
        - mitigation: Set to RemedialProcedure variable outputted from Acunetix 360 Scanner if it is present.
        - impact: Set to Impact variable outputted from Acunetix 360 Scanner if it is present.
        - date: Set to FirstSeenDate variable outputted from Acunetix 360 Scanner if present. If not, it is set to Generated variable from output.
        - cwe: Set to converted cwe in Classification variable outputted from Acunetix 360 Scanner if it is present.
        - static_finding: Set to True.
        - cvssv3: Set to converted cvssv3 in Classification variable outputted from Acunetix 360 Scanner if it is present.
        - risk_accepted: Set to True if AcceptedRisk is present in State variable outputted from Acunetix 360 Scanner. No value if variable is not present.
        - active: Set to false.
        """
        return [
            "title",
            "severity",
            "description",
            "false_p",
            "static_finding",
            "dynamic_finding",
            "nb_occurences",
            "impact",
            "mitigation",
            "date",
            "cwe",
            "cvssv3",
            "risk_accepted",
            "active",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Acunetix XML Parser.

        Fields:
        - title: Set to the name outputted by the Acunetix XML Scanner.
        - description: Set to description, Details, and TechnivalDetails variables outputted from Acunetix XML Scanner.

        Return the list of fields used for deduplication in the Acunetix 360 Parser.

        Fields:
        - title: Set to the name outputted by the Acunetix 360 Scanner.
        - description: Set to Description variable outputted from Acunetix 360 Scanner.
        """
        return [
            "title",
            "description",
        ]

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
