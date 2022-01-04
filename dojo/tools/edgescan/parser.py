import json

from dojo.models import Endpoint, Finding
from dojo.tools.edgescan.importer import EdgescanApiImporter

ES_SEVERITIES = {1: "Info", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}
SCAN_EDGESCAN_API = 'Edgescan API Scan'
SCAN_EDGESCAN = 'Edgescan Scan'


class EdgescanParser(object):
    """
    Import from Edgescan API or JSON file
    """

    def get_scan_types(self):
        return [SCAN_EDGESCAN, SCAN_EDGESCAN_API]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        if scan_type == SCAN_EDGESCAN_API:
            return "Edgescan findings can be imported by API."
        return "Edgescan findings can be imported in JSON format."

    def requires_file(self, scan_type):
        return False if scan_type == SCAN_EDGESCAN_API else True

    def requires_tool_type(self, scan_type):
        return 'Edgescan' if scan_type == SCAN_EDGESCAN_API else None

    def get_findings(self, file, test):
        try:
            if file:
                serialized_data = file.read()
                try:
                    data = json.loads(str(serialized_data, "utf-8"))
                except:
                    data = json.loads(serialized_data)
            else:
                data = EdgescanApiImporter().get_findings(test)
        except:
            raise Exception("Invalid details provided")

        return self.process_vulnerabilities(test, data)

    def process_vulnerabilities(self, test, vulnerabilities):
        findings = []

        for vulnerability in vulnerabilities:
            findings.append(self.make_finding(test, vulnerability))

        return findings

    def make_finding(self, test, vulnerability):
        finding = Finding(test=test)
        finding.title = vulnerability["name"]
        finding.date = vulnerability["date_opened"][:10]
        if vulnerability["cwes"]:
            finding.cwe = int(vulnerability["cwes"][0][4:])
        if vulnerability["cves"]:
            finding.cve = str(vulnerability["cves"])
        finding.url = vulnerability["location"]
        finding.severity = ES_SEVERITIES[vulnerability["severity"]]
        finding.description = vulnerability["description"]
        finding.mitigation = vulnerability["remediation"]
        finding.active = True
        finding.verified = True
        finding.false_p = False
        finding.duplicate = False
        finding.out_of_scope = False
        finding.numerical_severity = Finding.get_numerical_severity(ES_SEVERITIES[vulnerability["severity"]])
        finding.tags = vulnerability["asset_tags"]
        finding.unique_id_from_tool = vulnerability["id"]

        finding.unsaved_endpoints = [Endpoint.from_uri(vulnerability["location"])]

        return finding
