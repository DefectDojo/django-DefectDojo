import json
from dojo.models import Finding


class OSVScannerParser(object):

    def get_scan_types(self):
        return ["OSV Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "OSV Scan"

    def get_description_for_scan_types(self, scan_type):
        return "OSV scan output can be imported in JSON format (option --format json)."

    def classify_severity(self, input):
        if input != "":
            if input == "MODERATE":
                severity = "Medium"
            else:
                severity = input.lower().capitalize()
        else:
            severity = "Low"
        return severity

    def get_findings(self, file, test):
        try:
            data = json.load(file)
        except json.decoder.JSONDecodeError:
            return []
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
                    vulnerabilitysummary = vulnerability.get("summary", "")
                    vulnerabilitydetails = vulnerability["details"]
                    vulnerabilitypackagepurl = vulnerability["affected"][0].get("package", "")
                    if vulnerabilitypackagepurl != "":
                        vulnerabilitypackagepurl = vulnerabilitypackagepurl["purl"]
                    cwe = vulnerability["affected"][0]["database_specific"].get("cwes", None)
                    if cwe is not None:
                        cwe = cwe[0]["cweId"]
                    reference = ""
                    for ref in vulnerability.get("references"):
                        reference += ref.get("url") + "\n"
                    description = vulnerabilitysummary + "\n"
                    description += "**source_type**: " + source_type + "\n"
                    description += "**package_ecosystem**: " + package_ecosystem + "\n"
                    description += "**vulnerabilitydetails**: " + vulnerabilitydetails + "\n"
                    description += "**vulnerabilitypackagepurl**: " + vulnerabilitypackagepurl + "\n"
                    sev = vulnerability.get("database_specific", {}).get("severity", "")
                    finding = Finding(
                        title=vulnerabilityid + "_" + package_name,
                        test=test,
                        description=description,
                        severity=self.classify_severity(sev),
                        static_finding=True,
                        dynamic_finding=False,
                        component_name=package_name,
                        component_version=package_version,
                        cwe=cwe,
                        cve=vulnerabilityid,
                        file_path=source_path,
                        references=reference,
                    )
                    findings.append(finding)
        return findings
