import json

from dojo.models import Finding


class GCloudArtifactScanParser:
    def get_scan_types(self):
        return ["Google Cloud Artifact Vulnerability Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import Google Cloud Artifact Vulnerability scans in JSON format."

    def parse_json(self, json_output):
        try:
            data = json_output.read()
            try:
                tree = json.loads(str(data, "utf-8"))
            except Exception:
                tree = json.loads(data)
        except Exception:
            msg = "Invalid format"
            raise ValueError(msg)
        return tree

    def get_findings(self, json_output, test):
        findings = []
        if json_output is None:
            return findings
        tree = self.parse_json(json_output)
        if tree:
            for severity in tree["package_vulnerability_summary"]["vulnerabilities"]:
                for vuln in tree["package_vulnerability_summary"]["vulnerabilities"][severity]:
                    description = "name: " + str(vuln["name"]) + "\n\n"
                    description += "resourceUri: " + str(vuln["resourceUri"]) + "\n"
                    description += "fixAvailable: " + str(vuln["vulnerability"]["fixAvailable"]) + "\n"
                    description += "packageIssue: " + str(vuln["vulnerability"]["packageIssue"]) + "\n"
                    description += "CVE: " + str(vuln["vulnerability"]["shortDescription"]) + "\n"
                    reference = ""
                    for ref in vuln["vulnerability"]["relatedUrls"]:
                        reference += ref["url"] + "\n"
                    finding = Finding(
                        title=vuln["noteName"],
                        test=test,
                        description=description,
                        severity=severity.lower().capitalize(),
                        references=reference,
                        component_name="affectedCPEUri: " + vuln["vulnerability"]["packageIssue"][0]["affectedCpeUri"] + " affectedPackage: " + vuln["vulnerability"]["packageIssue"][0]["affectedPackage"],
                        component_version=vuln["vulnerability"]["packageIssue"][0]["affectedVersion"]["fullName"],
                        static_finding=True,
                        dynamic_finding=False,
                        cvssv3_score=vuln["vulnerability"]["cvssScore"],
                    )
                    findings.append(finding)
        return findings
