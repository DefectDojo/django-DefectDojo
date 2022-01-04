import json

from dojo.models import Finding, Endpoint

ES_SEVERITIES = {1: "Info", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}

class EdgescanParser(object):

    def get_scan_types(self):
        return ["Edgescan Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON"

    def get_findings(self, file, test):
        if file is None:
            return list()

        try:
            data = file.read()
            try:
                deserialized = json.loads(str(data, "utf-8"))
            except:
                deserialized = json.loads(data)

            return self.process_vulnerabilities(test, deserialized)
        except:
            raise Exception("Invalid format")

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
        finding.vuln_id_from_tool = vulnerability["id"]
        finding.tags = vulnerability["asset_tags"]

        finding.unsaved_endpoints = [Endpoint.from_uri(vulnerability["location"])]

        return finding
