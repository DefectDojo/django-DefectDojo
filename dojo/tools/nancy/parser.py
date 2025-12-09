import json

from cvss.cvss3 import CVSS3
from cvss.cvss4 import CVSS4

from dojo.models import Finding


class NancyParser:
    def get_scan_types(self):
        return ["Nancy Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return ("Nancy output file (go list -json -deps ./... | nancy sleuth > "
                " nancy.json) can be imported in JSON format.")

    def requires_file(self, scan_type):
        """Return boolean indicating if parser requires a file to process."""
        return True

    def get_findings(self, scan_file, test):
        """Return the collection of Findings ingested."""
        data = json.load(scan_file)
        findings = None

        if "vulnerable" in data:
            findings = self.get_items(data["vulnerable"], test)
        else:
            msg = "Invalid format, unable to parse json."
            raise ValueError(msg)

        return findings

    def convert_cvss_score(self, raw_value):
        if raw_value is None:
            return "Info"
        val = float(raw_value)
        if val == 0.0:
            return "Info"
        if val < 4.0:
            return "Low"
        if val < 7.0:
            return "Medium"
        if val < 9.0:
            return "High"
        return "Critical"

    def get_items(self, vulnerable, test):
        findings = []
        for vuln in vulnerable:
            finding = None
            references = []
            if vuln["Vulnerabilities"]:
                comp_name = vuln["Coordinates"].split(":")[1].split("@")[0]
                comp_version = vuln["Coordinates"].split(":")[1].split("@")[1]

                references.append(vuln["Reference"])

                for associated_vuln in vuln["Vulnerabilities"]:
                    # create the finding object(s)
                    references.append(associated_vuln["Reference"])
                    vulnerability_ids = [associated_vuln["Cve"]]
                    finding = Finding(
                        title=associated_vuln["Title"],
                        description=associated_vuln["Description"],
                        test=test,
                        severity=self.convert_cvss_score(associated_vuln["CvssScore"]),
                        component_name=comp_name,
                        component_version=comp_version,
                        false_p=False,
                        duplicate=False,
                        out_of_scope=False,
                        static_finding=True,
                        dynamic_finding=False,
                        vuln_id_from_tool=associated_vuln.get("Id", associated_vuln.get("ID")),
                        references="\n".join(references),
                    )
                    finding.unsaved_vulnerability_ids = vulnerability_ids
                    cvss_vector = associated_vuln["CvssVector"]
                    # CVSSv3 vector
                    if cvss_vector and cvss_vector.startswith("CVSS:3."):
                        finding.cvssv3 = CVSS3(
                            associated_vuln["CvssVector"]).clean_vector()
                    elif cvss_vector and cvss_vector.startswith("CVSS:4."):
                        finding.cvssv4 = CVSS4(
                            associated_vuln["CvssVector"]).clean_vector()
                    # do we have a CWE?
                    if associated_vuln["Title"].startswith("CWE-"):
                        cwe = (associated_vuln["Title"]
                               .split(":")[0].split("-")[1])
                        finding.cwe = int(cwe)

                    findings.append(finding)

        return findings
