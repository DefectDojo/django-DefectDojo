import json
import hashlib
from datetime import datetime
from dojo.models import Finding, Endpoint


class TrustwaveFusionAPIParser(object):
    """
    Import Trustwave Fusion Report from its API in JSON format
    """

    def get_scan_types(self):
        return ["Trustwave Fusion API Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Trustwave Fusion API Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Trustwave Fusion API report file can be imported in JSON format"

    def get_findings(self, file, test):
        tree = json.load(file)
        items = {}

        # iterating through each vulnerability
        for node in tree["items"]:
            item = get_item(node, test)

            item_key = hashlib.sha256(
                "|".join([item.severity, item.title, item.description]).encode()
            ).hexdigest()

            if item_key in items:
                items[item_key].unsaved_endpoints.extend(item.unsaved_endpoints)
                items[item_key].nb_occurences += 1
            else:
                items[item_key] = item

        return list(items.values())

    def convert_severity(self, num_severity):
        """Convert severity value"""
        if num_severity >= -10:
            return "Low"
        elif -11 >= num_severity > -26:
            return "Medium"
        elif num_severity <= -26:
            return "High"
        else:
            return "Info"


def get_item(vuln, test):
    finding = Finding(
        test=test,
        unique_id_from_tool=vuln["id"],
        nb_occurences=1,
    )

    # Endpoint
    if vuln["location"]["url"] != "None":
        endpoint = Endpoint.from_uri(vuln["location"]["url"])
    elif (
        vuln["location"]["domain"] != "None"
    ):  # fallback to using old way of creating endpoints
        endpoint = Endpoint(
            protocol=vuln["location"]["applicationProtocol"],
            host=str(vuln["location"]["domain"]),
            port=vuln["location"]["port"],
        )
    else:
        endpoint = Endpoint(
            protocol=vuln["location"]["applicationProtocol"],
            host=str(vuln["location"]["ip"]),
            port=vuln["location"]["port"],
        )
    finding.unsaved_endpoints = [endpoint]

    finding.title = vuln["name"]

    # Description + CVEs
    description = vuln["classification"]
    cves = "no match"
    if "CVE-NO-MATCH" not in vuln["kb"]["cves"]:
        finding.cve = vuln["kb"]["cves"][0]
        # finding.cve = int(cve[9:])

        cves = ""
        for cve in vuln["kb"]["cves"]:
            cves += f"{cve}, "
        cves = cves[: len(cves) - 2]  # removing the comma and the blank space

    finding.description = description + "; CVEs: " + cves
    finding.severity = vuln["severity"].title()

    # Date
    date_str = vuln["updatedOn"]
    date_str = date_str[: len(date_str) - 3] + date_str[-2:]
    finding.date = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%f%z")

    return finding
