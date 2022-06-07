import json

from dojo.models import Endpoint, Finding
from dojo.tools.edgescan.importer import EdgescanImporter

ES_SEVERITIES = {1: "Info", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}
SCANTYPE_EDGESCAN = 'Edgescan Scan'


class EdgescanParser(object):
    """
    Import from Edgescan API or JSON file
    """

    def get_scan_types(self):
        return [SCANTYPE_EDGESCAN]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Edgescan findings can be imported by API or JSON file."

    def requires_tool_type(self, scan_type):
        return "Edgescan"

    def get_findings(self, file, test):
        if file:
            data = json.load(file)
        else:
            data = EdgescanImporter().get_findings(test)

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
            finding.unsaved_vulnerability_ids = vulnerability["cves"]
        if vulnerability["cvss_version"] == 3:
            if vulnerability["cvss_vector"]:
                finding.cvssv3 = vulnerability["cvss_vector"]
        finding.url = vulnerability["location"]
        finding.severity = ES_SEVERITIES[vulnerability["severity"]]
        finding.description = vulnerability["description"]
        finding.mitigation = vulnerability["remediation"]
        finding.active = True if vulnerability["status"] == "open" else False
        if vulnerability["asset_tags"]:
            finding.tags = vulnerability["asset_tags"].split(",")
        finding.unique_id_from_tool = vulnerability["id"]

        finding.unsaved_endpoints = [Endpoint.from_uri(vulnerability["location"])]

        return finding
