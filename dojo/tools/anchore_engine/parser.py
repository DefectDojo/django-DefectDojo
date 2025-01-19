import json
from dojo.models import Finding

class AnchoreEngineParser:
    def get_scan_types(self):
        return ["Anchore Engine Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Anchore Engine Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Anchore-CLI JSON vulnerability report format."

    def get_findings(self, filename, test):
        data = json.load(filename)
        dupes = {}
        for item in data.get("securityEvaluation", []):
            vulnerability_id = item.get("vulnerabilityId")

            title = (
                item["vulnerabilityId"]
                + " - "
                + item["package"]
                + " (" + item["packageType"] + ")"
            )

            # Finding details information
            findingdetail = (
                "**Image hash**: "
                + item.get("imageDigest", "None")
                + "\n\n"
            )
            findingdetail += "**Package**: " + item["package"] + "\n\n"
            findingdetail += "**Package Type**: " + item["packageType"] + "\n\n"
            findingdetail += "**CVEs**: " + item.get("cves", "None") + "\n\n"
            findingdetail += "**Fix Available**: " + item.get("fixAvailable", "None") + "\n\n"
            findingdetail += "**Fix Observed At**: " + item.get("fixObservedAt", "None") + "\n\n"
            findingdetail += "**Link**: " + item.get("link", "None") + "\n\n"
            findingdetail += "**CVSS Base Score**: " + str(item.get("nvdCvssBaseScore", "None")) + "\n\n"

            sev = item["severity"]
            if sev == "Negligible" or sev == "Unknown":
                sev = "Info"

            references = item.get("link", "None")

            dupe_key = "|".join(
                [
                    item.get("imageDigest", "None"),
                    item["vulnerabilityId"],
                    item["package"],
                    item["packageType"],
                ]
            )

            if dupe_key in dupes:
                find = dupes[dupe_key]
            else:
                dupes[dupe_key] = True

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
                dupes[dupe_key] = find

        return list(dupes.values())
