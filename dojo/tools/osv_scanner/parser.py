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
                    description = vulnerabilitysummary + "\n"
                    description += "**source_type**: " + source_type + "\n"
                    description += "**package_ecosystem**: " + package_ecosystem + "\n"
                    description += "**vulnerabilitydetails**: " + vulnerabilitydetails + "\n"
                    description += "**vulnerabilitypackagepurl**: " + vulnerabilitypackagepurl + "\n"
                    finding = Finding(
                        title=vulnerabilityid + "_" + package_name,
                        test=test,
                        description=description,
                        severity="High",
                        static_finding=True,
                        dynamic_finding=False,
                        component_name=package_name,
                        component_version=package_version,
                        cwe=cwe,
                        cve=vulnerabilityid,
                        file_path=source_path,
                        reference=reference,
                    )
                    findings.append(finding)
        return findings
