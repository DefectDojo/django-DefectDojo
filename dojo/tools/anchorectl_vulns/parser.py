import json
from dojo.models import Finding


class AnchoreCTLVulnsParser:
    def get_scan_types(self):
        return ["AnchoreCTL Vuln Report"]

    def get_label_for_scan_types(self, scan_type):
        return "AnchoreCTL Vuln Report"

    def get_description_for_scan_types(self, scan_type):
        return "AnchoreCTLs JSON vulnerability report format."

    def get_findings(self, filename, test):
        data = json.load(filename)
        dupes = {}
        
        # Check if the JSON structure contains 'metadata' and 'securityEvaluation' (new structure)
        if "metadata" in data and "securityEvaluation" in data:
            # New JSON structure
            metadata = data.get("metadata", {})
            image_digest = metadata.get("imageDigest", "None")
            vulnerabilities = data.get("securityEvaluation", [])
        else:
            # Original JSON structure (assumed)
            image_digest = "None"  # Default value
            vulnerabilities = data  # Assuming it's a list of vulnerabilities directly

        for vuln in vulnerabilities:
            # For the new structure, extract fields from 'securityEvaluation'
            if "vulnerabilityId" in vuln:
                vulnerability_id = vuln.get("vulnerabilityId")
                title = f"{vuln['vulnerabilityId']} - {vuln['package']} ({vuln['packageType']})"
                findingdetail = f"**Image hash**: {image_digest}\n\n"
                findingdetail += f"**Package**: {vuln['package']}\n\n"
                findingdetail += f"**Package path**: {vuln['path']}\n\n"
                findingdetail += f"**Package type**: {vuln['packageType']}\n\n"
                findingdetail += f"**Detected at**: {vuln['detectedAt']}\n\n"
                findingdetail += f"**Feed**: N/A\n\n"  # Placeholder, adjust as needed
                findingdetail += f"**CPE**: N/A\n\n"  # Placeholder, adjust as needed
                findingdetail += f"**Description**: {vuln.get('description', '<None>')}\n\n"

                sev = vuln["severity"]
                if sev == "Negligible" or sev == "Unknown":
                    sev = "Info"

                mitigation = f"Upgrade to {vuln['fixAvailable']}\n"
                mitigation += f"URL: {vuln['link']}\n"

                cvss_base_score = vuln.get("nvdCvssBaseScore", None)
                references = vuln["link"]

            else:
                # Handling the original JSON structure (with 'vuln', 'package', etc.)
                vulnerability_id = vuln.get("vuln")
                title = f"{vuln['vuln']} - {vuln['package']} ({vuln['packageType']})"
                findingdetail = f"**Image hash**: {image_digest}\n\n"
                findingdetail += f"**Package**: {vuln['package']}\n\n"
                findingdetail += f"**Package path**: {vuln.get('packagePath', 'N/A')}\n\n"
                findingdetail += f"**Package type**: {vuln['packageType']}\n\n"
                findingdetail += f"**Feed**: {vuln.get('feed', 'N/A')}/{vuln.get('feedGroup', 'N/A')}\n\n"
                findingdetail += f"**CPE**: {vuln.get('packageCpe', 'N/A')}\n\n"
                findingdetail += f"**Description**: {vuln.get('description', '<None>')}\n\n"

                sev = vuln["severity"]
                if sev == "Negligible" or sev == "Unknown":
                    sev = "Info"

                mitigation = f"Upgrade to {vuln['fix']}\n"
                mitigation += f"URL: {vuln['url']}\n"

                cvss_base_score = None
                if vuln["feed"] == "nvdv2" or vuln["feed"] == "vulnerabilities":
                    if "nvdData" in vuln and len(vuln["nvdData"]) > 0:
                        cvss_base_score = vuln["nvdData"][0]["cvssV3"]["baseScore"]
                else:
                    if "vendorData" in vuln and len(vuln["vendorData"]) > 0:
                        if (
                            "cvssV3" in vuln["vendorData"][0]
                            and vuln["vendorData"][0]["cvssV3"]["baseScore"] != -1
                        ):
                            cvss_base_score = vuln["vendorData"][0]["cvssV3"]["baseScore"]
                        elif len(vuln["vendorData"]) > 1:
                            if (
                                "cvssV3" in vuln["vendorData"][1]
                                and vuln["vendorData"][1]["cvssV3"]["baseScore"] != -1
                            ):
                                cvss_base_score = vuln["vendorData"][1]["cvssV3"]["baseScore"]

                references = vuln["url"]

            dupe_key = "|".join(
                [
                    image_digest,
                    vuln.get("vulnerabilityId", vuln.get("vuln")),
                    vuln["package"],
                    vuln.get("path", vuln.get("packagePath")),
                ]
            )

            if dupe_key in dupes:
                find = dupes[dupe_key]
            else:
                dupes[dupe_key] = True

                find = Finding(
                    title=title,
                    test=test,
                    cvssv3_score=cvss_base_score,
                    description=findingdetail,
                    severity=sev,
                    mitigation=mitigation,
                    references=references,
                    file_path=vuln.get("path", vuln.get("packagePath")),
                    component_name=vuln["package"],
                    component_version=vuln.get("packageVersion", "Unknown"),
                    url=vuln.get("url"),
                    static_finding=True,
                    dynamic_finding=False,
                    vuln_id_from_tool=vuln.get("vulnerabilityId", vuln.get("vuln")),
                )
                if vulnerability_id:
                    find.unsaved_vulnerability_ids = [vulnerability_id]
                dupes[dupe_key] = find

        return list(dupes.values())

