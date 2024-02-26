import json
from dojo.models import Finding


class OSVScannerParser(object):

    def get_scan_types(self):
        return ["OSV Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "OSV Scan"

    def get_description_for_scan_types(self, scan_type):
        return "OSV scan output can be imported in JSON format (option --format json)."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = list()
        for result in data["results"]:
            source_path = result["source"]["path"]
            source_type = result["source"]["type"]
            for package in result["packages"]:
                package_name = package["package"]["name"]
                package_version = package["package"]["version"]
                package_ecosystem = package["package"]["ecosystem"]
                for vulnerability in package["vulnerabilities"]:
                    vulnerabilityid = vulnerability["id"]
                    vulnerabilitysummary = vulnerability["summary"]
                    vulnerabilitydetails = vulnerability["details"]
                    vulnerabilitypackagepurl = vulnerability["affected"][0]["package"]["purl"]
                    cwe = vulnerability["affected"][0]["database_specific"]["cwes"][0]["cweId"]
                    reference = vulnerability["affected"][0]["references"][0]["url"]

        finding = Finding(
            title="title",
            test=test,
            description="description",
            severity="High",
            static_finding=False,
            dynamic_finding=True,
        )
        findings.append(finding)
        return findings
