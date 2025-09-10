import json
import re

from cvss.cvss4 import CVSS4  # Changed from cvss3 to cvss4

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

        return True

    def get_findings(self, scan_file, test):

        try:
            data = json.load(scan_file)
        except json.JSONDecodeError as e:
            msg = f"Invalid JSON format: {e}"
            raise ValueError(msg)

        if "vulnerable" in data and data["vulnerable"] is not None:
            return self.get_items(data["vulnerable"], test)
        else:
            # If 'vulnerable' is not present or is null, return empty list
            return []

    def get_items(self, vulnerable_list, test):

        findings = []
        for vuln in vulnerable_list:
            if not vuln.get("Vulnerabilities"):
                continue

            try:
                coordinates = vuln["Coordinates"].split(":")
                comp_info = coordinates[1].split("@")
                comp_name = comp_info[0]
                comp_version = comp_info[1]
            except (IndexError, KeyError):
                # Handle cases where coordinate parsing might fail
                continue

            for associated_vuln in vuln["Vulnerabilities"]:
                # The tool does not define severity, but it provides a CVSS vector,
                # which DefectDojo uses to calculate severity dynamically on save.
                severity = "Info"

                # Aggregate references
                references = [vuln.get("Reference"), associated_vuln.get("Reference")]
                references = "\n".join(filter(None, references))

                finding = Finding(
                    title=associated_vuln.get("Title", "N/A"),
                    description=associated_vuln.get("Description", "No description provided."),
                    test=test,
                    severity=severity,
                    component_name=comp_name,
                    component_version=comp_version,
                    false_p=False,
                    duplicate=False,
                    out_of_scope=False,
                    static_finding=True,
                    dynamic_finding=False,
                    vuln_id_from_tool=associated_vuln.get("ID"),  # Changed from "Id" to "ID"
                    references=references,
                )

                # Set vulnerability IDs (e.g., CVEs)
                if cve := associated_vuln.get("Cve"):
                    finding.unsaved_vulnerability_ids = [cve]

                # Process CVSSv4 vector if available
                if cvss_vector := associated_vuln.get("CvssVector"):
                    try:
                        # Store the cleaned CVSSv4 vector. DefectDojo will process it.
                        finding.cvssv3 = CVSS4(cvss_vector).clean_vector()
                    except Exception:
                        # Fallback or log error if vector is not valid CVSSv4
                        pass  # Or log a warning

                # Extract CWE if present in the title using regex for robustness
                if title := associated_vuln.get("Title", ""):
                    cwe_match = re.search(r"CWE-(\d+)", title, re.IGNORECASE)
                    if cwe_match:
                        try:
                            finding.cwe = int(cwe_match.group(1))
                        except (ValueError, IndexError):
                            pass  # Or log a warning

                findings.append(finding)

        return findings
