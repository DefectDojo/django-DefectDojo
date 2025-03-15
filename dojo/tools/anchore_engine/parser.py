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
        try:
            data = json.load(filename)
        except AttributeError:
            with open(filename, encoding="utf-8") as file:
                data = json.load(file)
        if data.get("metadata"):
            return self.get_findings_with_metadata(data, test)
        else:
            return self.get_findings_without_metadata(data, test)
    
    def get_findings_with_metadata(self, data, test):
        dupes = {}
        metadata = data.get("metadata", {})
        details = f"**Image hash**: {metadata.get('imageDigest', metadata.get('image_digest', 'None'))} \n\n"

        for item in data.get("securityEvaluation", []):
            vulnerability_id = item.get("vulnerabilityId", "Unknown")

            title = (
                vulnerability_id + "-" + item.get("package", "Unknown") + "(" + item.get("packageType", "Unknown") + ")"
            )

            details += f"**Package**: {item.get('package', 'Unknown')}\n\n"
            details += f"**Package path**: {item.get('path', 'Unknown')}\n\n"
            details += f"**Package type**: {item.get('packageType', 'Unknown')}\n\n"

            severity = item.get("severity", "Unknown")

            if severity.lower() in ["negligible", "unknown"]:
                severity = "Info"

            mitigation = "No fix available."

            if item.get("fixAvailable") and item["fixAvailable"] != "None":
                mitigation = f"Upgrade to: {' or '.join(item['fixAvailable'].split(','))}\n\n"
                mitigation += f"URL: {item.get('link', 'None')}"
            cvssv3_base_score = item.get("nvdCvssBaseScore")

            if isinstance(cvssv3_base_score, str) and cvssv3_base_score.replace(".", "", 1).isdigit():
                cvssv3_base_score = float(cvssv3_base_score)
            elif not isinstance(cvssv3_base_score, int | float):
                cvssv3_base_score = None

            references = item.get("link")

            dupe_key = "|".join(
                [
                    item.get("cves", "None"),
                    item.get("package", "None"),
                    item.get("packageType", "None"),
                    item.get("path", "None"),
                    item.get("severity", "None"),
                ],
            )

            if dupe_key in dupes:
                find = dupes[dupe_key]
            else:
                find = Finding(
                    title=title,
                    test=test,
                    cve=item.get("cves"),
                    cvssv3_score=cvssv3_base_score,
                    description=details,
                    severity=severity,
                    mitigation=mitigation,
                    references=references,
                    file_path=item.get("path"),
                    component_name=item.get("package"),
                    url=item.get("link"),
                    static_finding=True,
                    dynamic_finding=False,
                    vuln_id_from_tool=vulnerability_id,
                )

                if vulnerability_id:
                    find.unsaved_vulnerability_ids = [vulnerability_id]

                dupes[dupe_key] = find

        return list(dupes.values())

    def get_findings_without_metadata(self, data, test):
        dupes = {}
        for item in data["vulnerabilities"]:
            vulnerability_id = item.get("vuln")

            title = (
                item["vuln"]
                + " - "
                + item["package"]
                + "("
                + item["package_type"]
                + ")"
            )

            # Finding details information
            # depending on version image_digest/imageDigest
            findingdetail = (
                "**Image hash**: "
                + item.get("image_digest", item.get("imageDigest", "None"))
                + "\n\n"
            )
            findingdetail += "**Package**: " + item["package"] + "\n\n"
            findingdetail += (
                "**Package path**: " + item["package_path"] + "\n\n"
            )
            findingdetail += (
                "**Package type**: " + item["package_type"] + "\n\n"
            )
            findingdetail += (
                "**Feed**: " + item["feed"] + "/" + item["feed_group"] + "\n\n"
            )
            findingdetail += "**CPE**: " + item["package_cpe"] + "\n\n"
            findingdetail += (
                "**Description**: "
                + item.get("description", "<None>")
                + "\n\n"
            )

            sev = item["severity"]
            if sev == "Negligible" or sev == "Unknown":
                sev = "Info"

            mitigation = (
                "Upgrade to " + item["package_name"] + " " + item["fix"] + "\n"
            )
            mitigation += "URL: " + item["url"] + "\n"

            cvssv3_base_score = None
            if item["feed"] == "nvdv2" or item["feed"] == "vulnerabilities":
                if "nvd_data" in item and len(item["nvd_data"]) > 0:
                    cvssv3_base_score = item["nvd_data"][0]["cvss_v3"][
                        "base_score"
                    ]
            # there may be other keys, but taking a best guess here
            elif "vendor_data" in item and len(item["vendor_data"]) > 0:
                # sometimes cvssv3 in 1st element will have -1 for "not
                # set", but have data in the 2nd array item
                if (
                    "cvss_v3" in item["vendor_data"][0]
                    and item["vendor_data"][0]["cvss_v3"]["base_score"]
                    != -1
                ):
                    cvssv3_base_score = item["vendor_data"][0]["cvss_v3"][
                        "base_score"
                    ]
                elif len(item["vendor_data"]) > 1:
                    if (
                        "cvss_v3" in item["vendor_data"][1]
                        and item["vendor_data"][1]["cvss_v3"]["base_score"]
                        != -1
                    ):
                        cvssv3_base_score = item["vendor_data"][1][
                            "cvss_v3"
                        ]["base_score"]
            # cvssv3 score spec states value should be between 0.0 and 10.0
            # anchorage provides a -1.0 in some situations which breaks spec
            if (cvssv3_base_score
                and ((float(cvssv3_base_score) < 0)
                     or (float(cvssv3_base_score) > 10))):
                cvssv3_base_score = None

            references = item["url"]

            dupe_key = "|".join(
                [
                    item.get(
                        "image_digest", item.get("imageDigest", "None"),
                    ),  # depending on version image_digest/imageDigest
                    item["feed"],
                    item["feed_group"],
                    item["package_name"],
                    item["package_version"],
                    item["package_path"],
                    item["vuln"],
                ],
            )

            if dupe_key in dupes:
                find = dupes[dupe_key]
            else:
                dupes[dupe_key] = True

                find = Finding(
                    title=title,
                    test=test,
                    cvssv3_score=cvssv3_base_score,
                    description=findingdetail,
                    severity=sev,
                    mitigation=mitigation,
                    references=references,
                    file_path=item["package_path"],
                    component_name=item["package_name"],
                    component_version=item["package_version"],
                    url=item.get("url"),
                    static_finding=True,
                    dynamic_finding=False,
                    vuln_id_from_tool=item.get("vuln"),
                )
                if vulnerability_id:
                    find.unsaved_vulnerability_ids = [vulnerability_id]
                dupes[dupe_key] = find

        return list(dupes.values())
