import json
from dojo.models import Finding

class AnchoreEnterpriseParser:
    
    def get_scan_types(self):
        return ["Anchore Enterprise Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Anchore Enterprise Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Anchorectl JSON vulnerability report format."

    def get_findings(self, filename, test):
        # Open the file and load the JSON data
        with open(filename, 'r') as file:
            data = json.load(file)

        dupes = {}  # To store unique findings
        findings = []  # List to hold the final findings

        for item in data.get("securityEvaluation", []):
            vulnerability_id = item.get("vulnerabilityId")

            title = f"{item['vulnerabilityId']} - {item['package']} ({item['packageType']})"

            # Building the finding details information
            findingdetail = (
                f"**Image hash**: {item.get('imageDigest', 'None')}\n\n"
                f"**Package**: {item['package']}\n\n"
                f"**Package Type**: {item['packageType']}\n\n"
                f"**CVEs**: {item.get('cves', 'None')}\n\n"
                f"**Fix Available**: {item.get('fixAvailable', 'None')}\n\n"
                f"**Fix Observed At**: {item.get('fixObservedAt', 'None')}\n\n"
                f"**Link**: {item.get('link', 'None')}\n\n"
                f"**CVSS Base Score**: {item.get('nvdCvssBaseScore', 'None')}\n\n"
            )

            sev = item["severity"]
            if sev == "Negligible" or sev == "Unknown":
                sev = "Info"

            references = item.get("link", "None")

            # Creating a key to track duplicates
            dupe_key = "|".join([
                item.get("imageDigest", "None"),
                item["vulnerabilityId"],
                item["package"],
                item["packageType"]
            ])

            # Avoiding duplication of findings
            if dupe_key not in dupes:
                find = Finding(
                    title=title,
                    test=test,
                    cvssv3_score=item.get("nvdCvssBaseScore"),
                    description=findingdetail,
                    severity=sev,
                    references=references,
                    file_path="N/A",  # Package path is not available in the sample data
                    component_name=item["package"],
                    component_version=item.get("fixAvailable", "N/A"),
                    url=item.get("link"),
                    static_finding=True,
                    dynamic_finding=False,
                    vuln_id_from_tool=item.get("vulnerabilityId"),
                )

                if vulnerability_id:
                    find.unsaved_vulnerability_ids = [vulnerability_id]

                # Storing the finding to avoid duplication
                dupes[dupe_key] = find

        # Return a list of all findings, avoiding duplicates
        return list(dupes.values())
