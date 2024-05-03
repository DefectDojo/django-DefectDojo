import json

from cvss.cvss3 import CVSS3
from dojo.models import Finding


class NancyParser(object):
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
            raise ValueError("Invalid format, unable to parse json.")

        return findings

    def get_items(self, vulnerable, test):
        findings = []
        for vuln in vulnerable:
            finding = None
            severity = 'Info'
            # the tool does not define severity, however it
            # provides CVSSv3 vector which will calculate
            # severity dynamically on save()
            references = []
            if vuln['Vulnerabilities']:
                comp_name = vuln['Coordinates'].split(':')[1].split('@')[0]
                comp_version = vuln['Coordinates'].split(':')[1].split('@')[1]

                references.append(vuln['Reference'])

                for associated_vuln in vuln['Vulnerabilities']:
                    # create the finding object(s)
                    references.append(associated_vuln['Reference'])
                    vulnerability_ids = [associated_vuln['Cve']]
                    finding = Finding(
                        title=associated_vuln['Title'],
                        description=associated_vuln['Description'],
                        test=test,
                        severity=severity,
                        component_name=comp_name,
                        component_version=comp_version,
                        false_p=False,
                        duplicate=False,
                        out_of_scope=False,
                        static_finding=True,
                        dynamic_finding=False,
                        vuln_id_from_tool=associated_vuln["Id"],
                        cve=associated_vuln['Cve'],
                        references="\n".join(references),
                    )

                    finding.unsaved_vulnerability_ids = vulnerability_ids

                    # CVSSv3 vector
                    if associated_vuln['CvssVector']:
                        finding.cvssv3 = CVSS3(
                            associated_vuln['CvssVector']).clean_vector()

                    # do we have a CWE?
                    if associated_vuln['Title'].startswith('CWE-'):
                        cwe = (associated_vuln['Title']
                               .split(':')[0].split('-')[1])
                        finding.cwe = int(cwe)

                    findings.append(finding)

        return findings
