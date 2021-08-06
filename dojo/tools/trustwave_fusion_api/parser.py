import json
import hashlib
from datetime import datetime
from dojo.models import Finding, Endpoint
from cpe import CPE


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

    # Defining variables
    location = vuln["location"]

    # Endpoint
    if "url" in location and location["url"] != "None":
        endpoint = Endpoint.from_uri(location["url"])
    elif (
        "domain" in location and location["domain"] != "None"
    ):  # fallback to using old way of creating endpoints
        endpoint = Endpoint(
            protocol=location["applicationProtocol"],
            host=str(location["domain"]),
            port=location["port"],
        )
    else:  # no domain, use ip instead
        endpoint = Endpoint(
            protocol=location["applicationProtocol"],
            host=str(location["ip"]),
            port=location["port"],
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
    date_str = vuln["createdOn"]
    date_str = date_str[: len(date_str) - 3] + date_str[-2:]
    finding.date = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%f%z")

    # Component name and version
    if "applicationCpe" in location and location["applicationCpe"] != "None":
        cpe = CPE(location["applicationCpe"])
        component_name = cpe.get_vendor()[0] + ":" if len(cpe.get_vendor()) > 0 else ""
        component_name += cpe.get_product()[0] if len(cpe.get_product()) > 0 else ""
        finding.component_name = component_name if component_name else None
        finding.component_version = (
            cpe.get_version()[0] if len(cpe.get_version()) > 0 else None
        )

    return finding
